
#include <snet/cert_cache/cert_cache.hpp>
#include <snet/crypto/cert.hpp>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/bio.hpp>

#include <casket/utils/exception.hpp>

#include <openssl/txt_db.h>

#include <cstring>
#include <cassert>
#include <cerrno>
#include <fstream>
#include <memory>
#include <stdexcept>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>


using namespace casket;
using namespace snet::crypto;



std::string OneLineSummary(X509_NAME &name)
{
    char buffer[1024] = {};
    auto ptr = X509_NAME_oneline(&name, buffer, sizeof(buffer));
    return std::string(ptr);
}

bool sslDateIsInTheFuture(char const * date)
{
    ASN1_UTCTIME tm;
    tm.flags = 0;
    tm.type = 23;
    tm.data = (unsigned char *)date;
    tm.length = strlen(date);

    return (X509_cmp_current_time(&tm) > 0);
}

namespace snet
{

Lock::Lock(std::string const& aFilename)
    : filename(aFilename)
    , fd(-1)
{
}

bool Lock::locked() const
{
    return fd != -1;
}

void Lock::lock()
{
    fd = open(filename.c_str(), O_RDWR);
    if (fd == -1)
        throw RuntimeError("Failed to open file ", filename);

    if (flock(fd, LOCK_EX) != 0)
        throw RuntimeError("Failed to get a lock of ", filename);
}

void Lock::unlock()
{
    if (fd != -1)
    {
        flock(fd, LOCK_UN);
        close(fd);
        fd = -1;
    }
    else
        throw RuntimeError("Lock is already unlocked for ", filename);
}

Lock::~Lock()
{
    if (locked())
        unlock();
}

Locker::Locker(Lock& aLock)
    : weLocked(false)
    , lock(aLock)
{
    if (!lock.locked())
    {
        lock.lock();
        weLocked = true;
    }
}

Locker::~Locker()
{
    if (weLocked)
        lock.unlock();
}

CertificateDb::Row::Row()
    : width(cnlNumber)
{
    row = (char**)OPENSSL_malloc(sizeof(char*) * (width + 1));
    for (size_t i = 0; i < width + 1; ++i)
        row[i] = nullptr;
}

CertificateDb::Row::Row(char** aRow, size_t aWidth)
    : width(aWidth)
{
    row = aRow;
}

CertificateDb::Row::~Row()
{
    if (!row)
        return;

    void* max;
    if ((max = (void*)row[width]) != nullptr)
    {
        // It is an openSSL allocated row. The TXT_DB_read function stores the
        // index and row items one one memory segment. The row[width] points
        // to the end of buffer. We have to check for items in the array which
        // are not stored in this segment. These items should released.
        for (size_t i = 0; i < width + 1; ++i)
        {
            if (((row[i] < (char*)row) || (row[i] > max)) && (row[i] != nullptr))
                OPENSSL_free(row[i]);
        }
    }
    else
    {
        for (size_t i = 0; i < width + 1; ++i)
        {
            if (row[i])
                OPENSSL_free(row[i]);
        }
    }
    OPENSSL_free(row);
}

void CertificateDb::Row::reset()
{
    row = nullptr;
}

void CertificateDb::Row::setValue(size_t cell, char const* value)
{
    assert(cell < width);
    if (row[cell])
    {
        OPENSSL_free(row[cell]);
    }
    if (value)
    {
        row[cell] = static_cast<char*>(OPENSSL_malloc(sizeof(char) * (strlen(value) + 1)));
        memcpy(row[cell], value, sizeof(char) * (strlen(value) + 1));
    }
    else
        row[cell] = nullptr;
}

char** CertificateDb::Row::getRow()
{
    return row;
}

void CertificateDb::sq_TXT_DB_delete(TXT_DB* db, const char** row)
{
    if (!db)
        return;

    for (int i = 0; i < sk_OPENSSL_PSTRING_num(db->data); ++i)
    {
        const char** current_row = ((const char**)sk_OPENSSL_PSTRING_value(db->data, i));
        if (current_row == row)
        {
            sq_TXT_DB_delete_row(db, i);
            return;
        }
    }
}

#define countof(arr) (sizeof(arr) / sizeof(*arr))
void CertificateDb::sq_TXT_DB_delete_row(TXT_DB* db, int idx)
{
    char** rrow;
    rrow = (char**)sk_OPENSSL_PSTRING_delete(db->data, idx);

    if (!rrow)
        return;

    Row row(rrow, cnlNumber); // row wrapper used to free the rrow

    const Columns db_indexes[] = {cnlSerial, cnlKey};
    for (unsigned int i = 0; i < countof(db_indexes); ++i)
    {
        void* data = nullptr;
        if (LHASH_OF(OPENSSL_STRING)* fieldIndex = db->index[db_indexes[i]])
            data = lh_OPENSSL_STRING_delete(fieldIndex, rrow);
        if (data)
            assert(data == rrow);
    }
}

unsigned long CertificateDb::index_serial_hash(const char** a)
{
    const char* n = a[CertificateDb::cnlSerial];
    while (*n == '0')
        ++n;
    return OPENSSL_LH_strhash(n);
}

int CertificateDb::index_serial_cmp(const char** a, const char** b)
{
    const char *aa, *bb;
    for (aa = a[CertificateDb::cnlSerial]; *aa == '0'; ++aa)
        ;
    for (bb = b[CertificateDb::cnlSerial]; *bb == '0'; ++bb)
        ;
    return strcmp(aa, bb);
}

unsigned long CertificateDb::index_name_hash(const char** a)
{
    return (OPENSSL_LH_strhash(a[CertificateDb::cnlKey]));
}

int CertificateDb::index_name_cmp(const char** a, const char** b)
{
    return (strcmp(a[CertificateDb::cnlKey], b[CertificateDb::cnlKey]));
}

const std::string CertificateDb::db_file("index.txt");
const std::string CertificateDb::cert_dir("certs");
const std::string CertificateDb::size_file("size");

CertificateDb::CertificateDb(std::string const& aDb_path, size_t aMax_db_size, size_t aFs_block_size)
    : db_path(aDb_path)
    , db_full(aDb_path + "/" + db_file)
    , cert_full(aDb_path + "/" + cert_dir)
    , size_full(aDb_path + "/" + size_file)
    , max_db_size(aMax_db_size)
    , fs_block_size((aFs_block_size ? aFs_block_size : 2048))
    , dbLock(db_full)
{
}

bool CertificateDb::find(std::string const& key, const X509CertPtr& expectedOrig,
                              X509CertPtr& cert, KeyPtr& pkey)
{
    const Locker locker(dbLock);
    load();
    return pure_find(key, expectedOrig, cert, pkey);
}

bool CertificateDb::purgeCert(std::string const& key)
{
    const Locker locker(dbLock);
    load();
    if (!db)
        return false;

    if (!deleteByKey(key))
        return false;

    save();
    return true;
}

bool CertificateDb::addCertAndPrivateKey(std::string const& useKey, const X509CertPtr& cert,
                                              const KeyPtr& pkey,
                                              const X509CertPtr& orig)
{
    const Locker locker(dbLock);
    load();
    if (!db || !cert || !pkey)
        return false;

    if (useKey.empty())
        return false;

    Row row;
    ASN1_INTEGER* ai = X509_get_serialNumber(cert.get());
    std::string serial_string;
    BigNumPtr serial(ASN1_INTEGER_to_BN(ai, nullptr));
    {
        auto hex_bn = BN_bn2hex(serial.get());
        serial_string = std::string(hex_bn);
        OPENSSL_free(hex_bn);
    }
    row.setValue(cnlSerial, serial_string.c_str());
    char** rrow = TXT_DB_get_by_index(db.get(), cnlSerial, row.getRow());
    // We are creating certificates with unique serial numbers. If the serial
    // number is found in the database, the same certificate is already stored.
    if (rrow != nullptr)
    {
        // TODO: check if the stored row is valid.
        return true;
    }

    // Remove any entry with given key
    deleteByKey(useKey);

    // check db size while trying to minimize calls to size()
    size_t dbSize = size();
    if ((dbSize == 0 && hasRows()) || (dbSize > 0 && !hasRows()) || (dbSize > 10 * max_db_size))
    {
        // Invalid database size, rebuild
        dbSize = rebuildSize();
    }
    while (dbSize > max_db_size && deleteInvalidCertificate())
    {
        dbSize = size(); // get the current database size
        // and try to find another invalid certificate if needed
    }
    // there are no more invalid ones, but there must be valid certificates
    while (dbSize > max_db_size)
    {
        if (!deleteOldestCertificate())
        {
            rebuildSize(); // No certificates in database.Update the size file.
            save();        // Some entries may have been removed. Update the index file.
            return false;  // errors prevented us from freeing enough space
        }
        dbSize = size(); // get the current database size
    }

    const auto tm = X509_getm_notAfter(cert.get());
    row.setValue(cnlExp_date, std::string(reinterpret_cast<char*>(tm->data), tm->length).c_str());
    const auto subject = OneLineSummary(*X509_get_subject_name(cert.get()));
    row.setValue(cnlName, subject.c_str());
    row.setValue(cnlKey, useKey.c_str());

    if (!TXT_DB_insert(db.get(), row.getRow()))
    {
        // failed to add index (???) but we may have already modified
        // the database so save before exit
        save();
        return false;
    }
    rrow = row.getRow();
    row.reset();

    std::string filename(cert_full + "/" + serial_string + ".pem");
    if (!WriteEntry(filename.c_str(), cert, pkey, orig))
    {
        // remove row from txt_db and save
        sq_TXT_DB_delete(db.get(), (const char**)rrow);
        save();
        return false;
    }
    addSize(filename);

    save();
    return true;
}

void CertificateDb::Create(std::string const& db_path)
{
    if (db_path == "")
        throw RuntimeError("Path to db is empty");
    std::string db_full(db_path + "/" + db_file);
    std::string cert_full(db_path + "/" + cert_dir);
    std::string size_full(db_path + "/" + size_file);

    if (mkdir(db_path.c_str(), 0750))
        throw RuntimeError("Cannot create {}", db_path);

    if (mkdir(cert_full.c_str(), 0750))
        throw RuntimeError("Cannot create {}", cert_full);

    std::ofstream size(size_full.c_str());
    if (size)
        size << 0;
    else
        throw RuntimeError("Cannot open ", size_full, " to open");
    std::ofstream db(db_full.c_str());
    if (!db)
        throw RuntimeError("Cannot open ", db_full, " to open");
}

void CertificateDb::Check(std::string const& db_path, size_t max_db_size, size_t fs_block_size)
{
    CertificateDb db(db_path, max_db_size, fs_block_size);
    db.load();

    // Call readSize to force rebuild size file in the case it is corrupted
    (void)db.readSize();
}

size_t CertificateDb::rebuildSize()
{
    size_t dbSize = 0;
    for (int i = 0; i < sk_OPENSSL_PSTRING_num(db.get()->data); ++i)
    {
        const char** current_row = ((const char**)sk_OPENSSL_PSTRING_value(db.get()->data, i));
        const std::string filename(cert_full + "/" + current_row[cnlSerial] + ".pem");
        const size_t fSize = getFileSize(filename);
        dbSize += fSize;
    }
    writeSize(dbSize);
    return dbSize;
}

bool CertificateDb::pure_find(std::string const& key, const X509CertPtr& expectedOrig,
                                   X509CertPtr& cert, KeyPtr& pkey)
{
    if (!db)
        return false;

    Row row;
    row.setValue(cnlKey, key.c_str());

    char** rrow = TXT_DB_get_by_index(db.get(), cnlKey, row.getRow());
    if (rrow == nullptr)
        return false;

    if (!sslDateIsInTheFuture(rrow[cnlExp_date]))
        return false;

    X509CertPtr storedOrig;
    // read cert and pkey from file.
    std::string filename(cert_full + "/" + rrow[cnlSerial] + ".pem");
    if (!ReadEntry(filename.c_str(), cert, pkey, storedOrig))
        return false;

    if (!storedOrig && !expectedOrig)
    {
        return true;
    }
    else
    {
        return Cert::isEqual(expectedOrig, storedOrig);
    }
}

size_t CertificateDb::size()
{
    return readSize();
}

void CertificateDb::addSize(std::string const& filename)
{
    // readSize will rebuild 'size' file if missing or it is corrupted
    size_t dbSize = readSize();
    dbSize += getFileSize(filename);
    writeSize(dbSize);
}

void CertificateDb::subSize(std::string const& filename)
{
    // readSize will rebuild 'size' file if missing or it is corrupted
    size_t dbSize = readSize();
    const size_t fileSize = getFileSize(filename);
    dbSize = dbSize > fileSize ? dbSize - fileSize : 0;
    writeSize(dbSize);
}

size_t CertificateDb::readSize()
{
    std::ifstream ifstr(size_full.c_str());
    size_t db_size = 0;
    if (!ifstr || !(ifstr >> db_size))
        return rebuildSize();
    return db_size;
}

void CertificateDb::writeSize(size_t db_size)
{
    std::ofstream ofstr(size_full.c_str());
    if (!ofstr)
        throw RuntimeError("cannot write \"", size_full, "\" file");
    ofstr << db_size;
}

size_t CertificateDb::getFileSize(std::string const& filename)
{
    std::ifstream file(filename.c_str(), std::ios::binary);
    if (!file)
        return 0;
    file.seekg(0, std::ios_base::end);
    const std::streampos file_size = file.tellg();
    if (file_size < 0)
        return 0;
    return ((static_cast<size_t>(file_size) + fs_block_size - 1) / fs_block_size) * fs_block_size;
}

void CertificateDb::load()
{
    // Load db from file.
    BioPtr in(BIO_new(BIO_s_file()));
    if (!in || BIO_read_filename(in.get(), db_full.c_str()) <= 0)
        throw RuntimeError("Uninitialized SSL certificate database directory: {}"
                                   ". To initialize, run \"security_file_certgen -c -s {}.", db_path, db_path);

    bool corrupt = false;
    TxtDbPtr temp_db(TXT_DB_read(in.get(), cnlNumber));
    if (!temp_db)
        corrupt = true;

    // Create indexes in db.
    if (!corrupt && !TXT_DB_create_index(temp_db.get(), cnlSerial, nullptr, LHASH_HASH_FN(index_serial_hash),
                                         LHASH_COMP_FN(index_serial_cmp)))
        corrupt = true;

    if (!corrupt && !TXT_DB_create_index(temp_db.get(), cnlKey, nullptr, LHASH_HASH_FN(index_name_hash),
                                         LHASH_COMP_FN(index_name_cmp)))
        corrupt = true;

    if (corrupt)
        throw RuntimeError("The SSL certificate database ", db_path, " is corrupted. Please rebuild");

    db.reset(temp_db.release());
}

void CertificateDb::save()
{
    if (!db)
        throw RuntimeError("The certificates database is not loaded");

    // To save the db to file,  create a new BIO with BIO file methods.
    BioPtr out(BIO_new(BIO_s_file()));
    if (!out || !BIO_write_filename(out.get(), const_cast<char*>(db_full.c_str())))
        throw RuntimeError("Failed to initialize ", db_full, " file for writing");

    if (TXT_DB_write(out.get(), db.get()) < 0)
        throw RuntimeError("Failed to write ", db_full, " file");
}

// Normally defined in defines.h file
void CertificateDb::deleteRow(const char** row, int rowIndex)
{
    const std::string filename(cert_full + "/" + row[cnlSerial] + ".pem");
    sq_TXT_DB_delete_row(db.get(), rowIndex);

    subSize(filename);
    int ret = remove(filename.c_str());
    if (ret < 0 && errno != ENOENT)
        throw RuntimeError("Failed to remove certificate file ", filename, " from db");
}

bool CertificateDb::deleteInvalidCertificate()
{
    if (!db)
        return false;

    bool removed_one = false;
    for (int i = 0; i < sk_OPENSSL_PSTRING_num(db.get()->data); ++i)
    {
        const char** current_row = ((const char**)sk_OPENSSL_PSTRING_value(db.get()->data, i));

        if (!sslDateIsInTheFuture(current_row[cnlExp_date]))
        {
            deleteRow(current_row, i);
            removed_one = true;
            break;
        }
    }

    if (!removed_one)
        return false;
    return true;
}

bool CertificateDb::deleteOldestCertificate()
{
    if (!hasRows())
        return false;

    const char** row = (const char**)sk_OPENSSL_PSTRING_value(db.get()->data, 0);

    deleteRow(row, 0);

    return true;
}

bool CertificateDb::deleteByKey(std::string const& key)
{
    if (!db)
        return false;

    for (int i = 0; i < sk_OPENSSL_PSTRING_num(db.get()->data); ++i)
    {
        const char** current_row = ((const char**)sk_OPENSSL_PSTRING_value(db.get()->data, i));
        if (key == current_row[cnlKey])
        {
            deleteRow(current_row, i);
            return true;
        }
    }
    return false;
}

bool CertificateDb::hasRows() const
{
    if (!db)
        return false;

    if (sk_OPENSSL_PSTRING_num(db.get()->data) == 0)
        return false;
    return true;
}

bool CertificateDb::WriteEntry(const std::string& filename, const X509CertPtr& cert,
                                    const KeyPtr& pkey, const X509CertPtr& orig)
{
    auto bio = BioTraits::openFile(filename, "wb");

    Cert::toBio(cert, bio);
    AsymmKey::toBio(KeyType::Private, pkey, bio, Encoding::PEM);
    Cert::toBio(orig, bio);

    return true;
}

bool CertificateDb::ReadEntry(std::string filename, X509CertPtr& cert, KeyPtr& pkey,
                                   X509CertPtr& orig)
{
    auto bio = BioTraits::openFile(filename, "rb");

    cert = Cert::fromBio(bio);
    pkey = AsymmKey::fromBio(KeyType::Private, bio, Encoding::PEM);
    orig = Cert::fromBio(bio);

    return true;
}

} // namespace snet