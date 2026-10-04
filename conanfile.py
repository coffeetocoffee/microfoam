# SPDX-License-Identifier: MIT
from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout


class MicrofoamConan(ConanFile):
    name = "microfoam"
    version = "1.9.3"
    package_type = "library"
    license = "MIT"
    url = "https://example.invalid/microfoam"
    description = "C99 embedded firmware delta-update library"
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "build_tests": [True, False],
        "strict": [True, False],
    }
    default_options = {
        "shared": False,
        "build_tests": False,
        "strict": True,
    }
    exports_sources = "CMakeLists.txt", "include/*", "src/*", "docs/*", "LICENSE"

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure(variables={
            "BUILD_SHARED_LIBS": "ON" if self.options.shared else "OFF",
            "MCF_BUILD_TESTS": "ON" if self.options.build_tests else "OFF",
            "MCF_STRICT": "ON" if self.options.strict else "OFF",
            "MCF_ENABLE_LZMA": "OFF",
            "MCF_ENABLE_SODIUM": "OFF",
        })
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["microfoam"]
