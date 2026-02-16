#include <gtest/gtest.h>

#include <fdpi/protocol/ldap.hpp>

#include <vector>

TEST(LdapDecoder, ParsesBindRequest) {
    // LDAP BindRequest: messageId=1, version=3, dn="cn=admin"
    std::vector<uint8_t> data = {
        0x30, 0x16,       // SEQUENCE len=22
        0x02, 0x01, 0x01, // INTEGER messageId=1
        0x60, 0x11,       // BindRequest len=17
        0x02, 0x01, 0x03, // INTEGER version=3
        0x04, 0x08, 0x63, 0x6E, 0x3D,
        0x61, 0x64, 0x6D, 0x69, 0x6E, // OCTET STRING "cn=admin"
        0x80, 0x02, 0x70, 0x77        // context [0] password "pw"
    };
    size_t offset = 0;
    auto result = fdpi::decodeLdap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageId, 1u);
    EXPECT_EQ(result->operation, fdpi::LdapOperation::BindRequest);
    ASSERT_TRUE(result->ldapVersion.has_value());
    EXPECT_EQ(*result->ldapVersion, 3);
    ASSERT_TRUE(result->bindDn.has_value());
    EXPECT_EQ(*result->bindDn, "cn=admin");
    EXPECT_EQ(offset, data.size());
}

TEST(LdapDecoder, ParsesBindResponse) {
    // LDAP BindResponse: messageId=1
    std::vector<uint8_t> data = {
        0x30, 0x0C,       // SEQUENCE len=12
        0x02, 0x01, 0x01, // messageId=1
        0x61, 0x07,       // BindResponse len=7
        0x0A, 0x01, 0x00, // ENUMERATED resultCode=0
        0x04, 0x00,       // matchedDN ""
        0x04, 0x00        // diagnosticMessage ""
    };
    size_t offset = 0;
    auto result = fdpi::decodeLdap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageId, 1u);
    EXPECT_EQ(result->operation, fdpi::LdapOperation::BindResponse);
    EXPECT_FALSE(result->ldapVersion.has_value());
    EXPECT_FALSE(result->bindDn.has_value());
}

TEST(LdapDecoder, ParsesSearchRequest) {
    // LDAP SearchRequest: messageId=2
    std::vector<uint8_t> data = {
        0x30, 0x0C,       // SEQUENCE
        0x02, 0x01, 0x02, // messageId=2
        0x63, 0x07,       // SearchRequest len=7
        0x04, 0x00,       // baseObject ""
        0x0A, 0x01, 0x00, // scope=base
        0x0A, 0x01, 0x00  // derefAliases
    };
    size_t offset = 0;
    auto result = fdpi::decodeLdap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageId, 2u);
    EXPECT_EQ(result->operation, fdpi::LdapOperation::SearchRequest);
}

TEST(LdapDecoder, ParsesSearchResultDone) {
    // LDAP SearchResultDone: messageId=2
    std::vector<uint8_t> data = {
        0x30, 0x0C,       // SEQUENCE
        0x02, 0x01, 0x02, // messageId=2
        0x65, 0x07,       // SearchResultDone len=7
        0x0A, 0x01, 0x00, // resultCode=0
        0x04, 0x00,       // matchedDN
        0x04, 0x00        // diagnosticMessage
    };
    size_t offset = 0;
    auto result = fdpi::decodeLdap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageId, 2u);
    EXPECT_EQ(result->operation, fdpi::LdapOperation::SearchResultDone);
}

TEST(LdapDecoder, ExtractsMessageId) {
    // LDAP BindResponse with messageId=42
    std::vector<uint8_t> data = {0x30, 0x0C,       // SEQUENCE
                                 0x02, 0x01, 0x2A, // messageId=42
                                 0x61, 0x07,       // BindResponse
                                 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeLdap(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->messageId, 42u);
}

TEST(LdapDecoder, ExtractsBindDn) {
    // LDAP BindRequest with DN "uid=jdoe,dc=example,dc=com"
    std::string dn = "uid=jdoe,dc=example,dc=com";
    std::vector<uint8_t> data = {
        0x30, static_cast<uint8_t>(7 + dn.size()), // SEQUENCE
        0x02, 0x01,
        0x01,                                          // messageId=1
        0x60, static_cast<uint8_t>(3 + 2 + dn.size()), // BindRequest
        0x02, 0x01,
        0x03,                                 // version=3
        0x04, static_cast<uint8_t>(dn.size()) // DN OCTET STRING
    };
    data.insert(data.end(), dn.begin(), dn.end());
    size_t offset = 0;
    auto result = fdpi::decodeLdap(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->bindDn.has_value());
    EXPECT_EQ(*result->bindDn, dn);
}

TEST(LdapDecoder, RejectsTruncated) {
    // Truncated: SEQUENCE claims len=22 but only 3 bytes follow
    std::vector<uint8_t> data = {0x30, 0x16, 0x02, 0x01, 0x01};
    size_t offset = 0;
    auto result = fdpi::decodeLdap(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(LdapDecoder, RejectsMalformedAsn1) {
    // Invalid: not a SEQUENCE tag
    std::vector<uint8_t> data = {0x31, 0x06, 0x02, 0x01, 0x01, 0x60, 0x01, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeLdap(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::MalformedPacket);
}
