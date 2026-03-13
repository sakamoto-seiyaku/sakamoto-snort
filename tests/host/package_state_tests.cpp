#include <PackageState.hpp>

#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>

namespace {

class TempDir {
public:
    TempDir() {
        const auto base = std::filesystem::temp_directory_path() / "sucre-snort-host-tests";
        std::filesystem::create_directories(base);

        for (uint32_t attempt = 0; attempt < 1024; ++attempt) {
            const auto candidate =
                base / ("case-" + std::to_string(::getpid()) + "-" + std::to_string(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(candidate, error)) {
                path_ = candidate;
                return;
            }
        }

        throw std::runtime_error("failed to create unique temporary directory");
    }

    ~TempDir() { std::filesystem::remove_all(path_); }

    std::filesystem::path writeFile(const std::string &name, const std::string &content) const {
        const auto path = path_ / name;
        std::ofstream out(path, std::ios::out | std::ios::binary);
        out << content;
        out.close();
        return path;
    }

private:
    std::filesystem::path path_;
};

void appendBe16(std::string &out, const uint16_t value) {
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}

void appendUtf(std::string &out, const std::string &text) {
    appendBe16(out, static_cast<uint16_t>(text.size()));
    out.append(text);
}

void appendInternedUtf(std::string &out, const std::string &text) {
    appendBe16(out, 0xffff);
    appendUtf(out, text);
}

std::string buildPackageRestrictionsAbx(const bool omitNameAttr = false) {
    std::string out("ABX\0", 4);

    out.push_back(static_cast<char>(0x10));
    out.push_back(static_cast<char>(0x22));
    appendUtf(out, "package-restrictions");

    out.push_back(static_cast<char>(0x22));
    appendUtf(out, "pkg");
    if (!omitNameAttr) {
        out.push_back(static_cast<char>(0x2f));
        appendInternedUtf(out, "name");
        appendUtf(out, "com.example.alpha");
    }
    out.push_back(static_cast<char>(0x23));
    appendUtf(out, "pkg");

    out.push_back(static_cast<char>(0x22));
    appendUtf(out, "package");
    out.push_back(static_cast<char>(0x2f));
    appendInternedUtf(out, "name");
    appendUtf(out, "com.example.beta");
    out.push_back(static_cast<char>(0xdf));
    appendInternedUtf(out, "inst");
    out.push_back(static_cast<char>(0x23));
    appendUtf(out, "package");

    out.push_back(static_cast<char>(0x23));
    appendUtf(out, "package-restrictions");
    out.push_back(static_cast<char>(0x11));

    return out;
}

TEST(PackageStateTest, ValidatesPackageNames) {
    EXPECT_TRUE(PackageState::isValidPackageName("com.example.app"));
    EXPECT_TRUE(PackageState::isValidPackageName("pkg-name_1"));
    EXPECT_FALSE(PackageState::isValidPackageName(""));
    EXPECT_FALSE(PackageState::isValidPackageName("bad..name"));
    EXPECT_FALSE(PackageState::isValidPackageName("bad/name"));
    EXPECT_FALSE(PackageState::isValidPackageName("bad\\name"));
    EXPECT_FALSE(PackageState::isValidPackageName(std::string(257, 'a')));
}

TEST(PackageStateTest, ParsesPackagesListFile) {
    TempDir tempDir;
    const auto path = tempDir.writeFile(
        "packages.list",
        "com.example.alpha 10001 0 /data/user/0 default:targetSdkVersion=35 none 0 0 1\n"
        "com.example.beta 10002 0 /data/user/0 default:targetSdkVersion=35 none 0 0 1\n"
        "com.example.shared 9999 0 /data/user/0 default:targetSdkVersion=35 none 0 0 1\n"
        "com.example.alpha.feature 10001 0 /data/user/0 default:targetSdkVersion=35 none 0 0 1\n");

    PackageState::PackagesListSnapshot snapshot;
    std::string error;

    ASSERT_TRUE(PackageState::parsePackagesListFile(path.c_str(), snapshot, &error));
    EXPECT_TRUE(error.empty());
    ASSERT_EQ(snapshot.packageToAppId.size(), 3u);
    EXPECT_EQ(snapshot.packageToAppId.at("com.example.alpha"), 10001u);
    EXPECT_EQ(snapshot.packageToAppId.at("com.example.beta"), 10002u);
    EXPECT_EQ(snapshot.packageToAppId.at("com.example.alpha.feature"), 10001u);
    EXPECT_EQ(snapshot.packageToAppId.count("com.example.shared"), 0u);
    ASSERT_EQ(snapshot.appIdToNames.count(10001u), 1u);
    EXPECT_EQ(snapshot.appIdToNames.at(10001u).size(), 2u);
}

TEST(PackageStateTest, RejectsConflictingAppId) {
    TempDir tempDir;
    const auto path = tempDir.writeFile(
        "packages.list",
        "com.example.alpha 10001 0 /data/user/0 default none 0 0 1\n"
        "com.example.alpha 10002 0 /data/user/0 default none 0 0 1\n");

    PackageState::PackagesListSnapshot snapshot;
    std::string error;

    ASSERT_FALSE(PackageState::parsePackagesListFile(path.c_str(), snapshot, &error));
    EXPECT_EQ(error, "conflicting appId for package");
}

TEST(PackageStateTest, RejectsMalformedPackagesListLine) {
    TempDir tempDir;
    const auto path = tempDir.writeFile("packages.list", "com.example.alpha\n");

    PackageState::PackagesListSnapshot snapshot;
    std::string error;

    ASSERT_FALSE(PackageState::parsePackagesListFile(path.c_str(), snapshot, &error));
    EXPECT_EQ(error, "malformed line (missing uid)");
}

TEST(PackageStateTest, ParsesPackageRestrictionsFile) {
    TempDir tempDir;
    const auto path = tempDir.writeFile(
        "package-restrictions.xml",
        "<package-restrictions>\n"
        "  <package name=\"com.example.alpha\" installed=\"true\" />\n"
        "  <pkg name=\"com.example.beta\" inst=\"0\" />\n"
        "  <pkg name=\"com.example.gamma\" />\n"
        "</package-restrictions>\n");

    PackageState::PackageRestrictionsSnapshot snapshot;
    std::string error;

    ASSERT_TRUE(PackageState::parsePackageRestrictionsFile(path.c_str(), snapshot, &error));
    EXPECT_TRUE(error.empty());
    EXPECT_TRUE(snapshot.installedPackages.contains("com.example.alpha"));
    EXPECT_FALSE(snapshot.installedPackages.contains("com.example.beta"));
    EXPECT_TRUE(snapshot.installedPackages.contains("com.example.gamma"));
}

TEST(PackageStateTest, RejectsMissingPackageNameInRestrictions) {
    TempDir tempDir;
    const auto path = tempDir.writeFile(
        "package-restrictions.xml",
        "<package-restrictions><pkg installed=\"true\" /></package-restrictions>\n");

    PackageState::PackageRestrictionsSnapshot snapshot;
    std::string error;

    ASSERT_FALSE(PackageState::parsePackageRestrictionsFile(path.c_str(), snapshot, &error));
    EXPECT_EQ(error, "missing pkg name attribute");
}

TEST(PackageStateTest, RejectsRestrictionsWithoutPackageEntries) {
    TempDir tempDir;
    const auto path = tempDir.writeFile(
        "package-restrictions.xml",
        "<package-restrictions></package-restrictions>\n");

    PackageState::PackageRestrictionsSnapshot snapshot;
    std::string error;

    ASSERT_FALSE(PackageState::parsePackageRestrictionsFile(path.c_str(), snapshot, &error));
    ASSERT_FALSE(error.empty());
    EXPECT_EQ(error.find("no <pkg>/<package> entries found"), 0u);
}

TEST(PackageStateTest, ParsesPackageRestrictionsAbxFile) {
    TempDir tempDir;
    const auto path = tempDir.writeFile("package-restrictions.xml", buildPackageRestrictionsAbx());

    PackageState::PackageRestrictionsSnapshot snapshot;
    std::string error;

    ASSERT_TRUE(PackageState::parsePackageRestrictionsFile(path.c_str(), snapshot, &error));
    EXPECT_TRUE(error.empty());
    EXPECT_TRUE(snapshot.installedPackages.contains("com.example.alpha"));
    EXPECT_FALSE(snapshot.installedPackages.contains("com.example.beta"));
}

TEST(PackageStateTest, RejectsAbxRestrictionsMissingPackageName) {
    TempDir tempDir;
    const auto path = tempDir.writeFile("package-restrictions.xml", buildPackageRestrictionsAbx(true));

    PackageState::PackageRestrictionsSnapshot snapshot;
    std::string error;

    ASSERT_FALSE(PackageState::parsePackageRestrictionsFile(path.c_str(), snapshot, &error));
    EXPECT_EQ(error, "missing pkg name attribute");
}

} // namespace
