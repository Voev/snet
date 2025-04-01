#include <errno.h>
#include <libmnl/libmnl.h>

int mnl_cb_run_my(const void* buf, size_t numbytes, unsigned int seq, unsigned int portid,
                  mnl_cb_t cb_data, void* data)
{
    int ret = MNL_CB_OK, len = numbytes;
    const struct nlmsghdr* nlh = (struct nlmsghdr*)buf;

    while (mnl_nlmsg_ok(nlh, len))
    {
        /* check message source */
        if (!mnl_nlmsg_portid_ok(nlh, portid))
        {
            errno = ESRCH;
            return -1;
        }
        /* perform sequence tracking */
        if (!mnl_nlmsg_seq_ok(nlh, seq))
        {
            errno = EPROTO;
            return -1;
        }

        /* dump was interrupted */
        if (nlh->nlmsg_flags & NLM_F_DUMP_INTR)
        {
            errno = EINTR;
            return -1;
        }

        /* netlink data message handling */
        if (nlh->nlmsg_type >= NLMSG_MIN_TYPE)
        {
            if (cb_data)
            {
                ret = cb_data(nlh, data);
                if (ret <= MNL_CB_STOP)
                    goto out;
            }
        }
        else if (nlh->nlmsg_type == NLMSG_ERROR)
        {
            const struct nlmsgerr* err = (struct nlmsgerr*)mnl_nlmsg_get_payload(nlh);

            if (nlh->nlmsg_len < mnl_nlmsg_size(sizeof(struct nlmsgerr)))
            {
                errno = EBADMSG;
                return MNL_CB_ERROR;
            }
            /* Netlink subsystems returns the errno value with different signess */
            if (err->error < 0)
                errno = -err->error;
            else
                errno = err->error;

            return err->error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
        }
        else
        {
            ret = MNL_CB_STOP;
            goto out;
        }
        nlh = mnl_nlmsg_next(nlh, &len);
    }
out:
    return ret;
}
