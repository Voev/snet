import os
from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps

def get_version():
    version_file = os.path.join(os.path.dirname(__file__), "version.txt")
    with open(version_file, 'r', encoding='utf-8') as f:
        return f.read().strip()

class SecureNetwork(ConanFile):
    name = "snet"
    version = get_version()
    author = "Kirill Voyevodin (voev.kirill@gmail.com)"
    description = "Secure Network Toolkit"
    settings = "os", "compiler", "build_type", "arch"

    options = {
        "shared": [True, False],
        "enable_tests": [True, False],
        "enable_coverage": [True, False],
        "enable_asan": [True, False],
        "enable_tsan": [True, False],
        "enable_ubsan": [True, False]
    }

    default_options = {
        "shared": True,
        "enable_tests": False,
        "enable_coverage": False,
        "enable_asan": False,
        "enable_tsan": False,
        "enable_ubsan": False
    }

    def requirements(self):
        self.requires("openssl/1.1.1w", headers=True, libs=True, run=True)
        self.requires("zlib/1.3.1")
        self.requires("libpcap/1.10.4")
        if self.options.enable_tests:
            self.requires("gtest/1.15.0")

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")
            if self.options.enable_coverage:
                raise ConanInvalidConfiguration("Coverage not supported on Windows")

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")
        if self.options.enable_coverage and not self.options.enable_tests:
            raise ConanInvalidConfiguration("Coverage is not supported without tests")

    def layout(self):
        cmake_layout(self)
    
    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.variables["CMAKE_VERBOSE_MAKEFILE"] = "ON"
        tc.generate()

    def build(self):
        cmake_vars = {}
        cmake = CMake(self)
        if self.options.enable_tests:
            cmake_vars["ENABLE_UNIT_TESTS"] = "ON"
        if self.options.enable_coverage:
            cmake_vars["ENABLE_CODE_COVERAGE"] = "ON"
        if self.options.enable_asan:
            cmake_vars["ENABLE_ADDRESS_SANITIZER"] = "ON"
        if self.options.enable_tsan:
            cmake_vars["ENABLE_THREAD_SANITIZER"] = "ON"
        if self.options.enable_ubsan:
            cmake_vars["ENABLE_UB_SANITIZER"] = "ON"
        cmake.configure(variables=cmake_vars)
        cmake.build()
        if self.options.enable_tests:
            if self.options.enable_coverage:
                cmake.build(target="coverage")
            else:
                cmake.test()
                self.run(f"cmake --build . --target run_pcap_tests")
