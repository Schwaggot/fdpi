#include <gtest/gtest.h>
#include <fdpi/protocol/tls.hpp>
#include <vector>

TEST(TlsDecoder, ParsesClientHelloWithSNI) {
    // Simplified TLS ClientHello with SNI extension
    // TLS Record Header:
    //   ContentType: Handshake (22)
    //   Version: TLS 1.0 (0x0301)
    //   Length: (variable)
    // Handshake Header:
    //   Type: ClientHello (1)
    //   Length: (variable)
    // ClientHello:
    //   Version: TLS 1.2 (0x0303)
    //   Random: 32 bytes
    //   Session ID length: 0
    //   Cipher Suites length: 4
    //   Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
    //   Compression Methods length: 1
    //   Compression Methods: null (0)
    //   Extensions length: (variable)
    //   SNI extension

    std::string sni = "example.com";
    uint16_t sniLen = static_cast<uint16_t>(sni.size());

    // Build extensions
    std::vector<uint8_t> extensions;
    // SNI extension (type=0x0000)
    extensions.push_back(0x00); extensions.push_back(0x00);  // extension type: SNI
    uint16_t sniExtLen = static_cast<uint16_t>(sniLen + 5);
    extensions.push_back(static_cast<uint8_t>(sniExtLen >> 8));
    extensions.push_back(static_cast<uint8_t>(sniExtLen & 0xFF));
    uint16_t sniListLen = static_cast<uint16_t>(sniLen + 3);
    extensions.push_back(static_cast<uint8_t>(sniListLen >> 8));
    extensions.push_back(static_cast<uint8_t>(sniListLen & 0xFF));
    extensions.push_back(0x00);  // host name type
    extensions.push_back(static_cast<uint8_t>(sniLen >> 8));
    extensions.push_back(static_cast<uint8_t>(sniLen & 0xFF));
    for (char c : sni) extensions.push_back(static_cast<uint8_t>(c));

    // Build ClientHello body
    std::vector<uint8_t> clientHello;
    clientHello.push_back(0x03); clientHello.push_back(0x03);  // version: TLS 1.2
    // Random: 32 zero bytes
    for (int i = 0; i < 32; ++i) clientHello.push_back(0x00);
    clientHello.push_back(0x00);  // session ID length: 0
    // Cipher suites
    clientHello.push_back(0x00); clientHello.push_back(0x04);  // cipher suites length: 4
    clientHello.push_back(0x13); clientHello.push_back(0x01);  // TLS_AES_128_GCM_SHA256
    clientHello.push_back(0x13); clientHello.push_back(0x02);  // TLS_AES_256_GCM_SHA384
    // Compression methods
    clientHello.push_back(0x01);  // length: 1
    clientHello.push_back(0x00);  // null
    // Extensions
    uint16_t extLen = static_cast<uint16_t>(extensions.size());
    clientHello.push_back(static_cast<uint8_t>(extLen >> 8));
    clientHello.push_back(static_cast<uint8_t>(extLen & 0xFF));
    clientHello.insert(clientHello.end(), extensions.begin(), extensions.end());

    // Build Handshake message
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);  // ClientHello
    uint32_t chLen = static_cast<uint32_t>(clientHello.size());
    handshake.push_back(static_cast<uint8_t>((chLen >> 16) & 0xFF));
    handshake.push_back(static_cast<uint8_t>((chLen >> 8) & 0xFF));
    handshake.push_back(static_cast<uint8_t>(chLen & 0xFF));
    handshake.insert(handshake.end(), clientHello.begin(), clientHello.end());

    // Build TLS Record
    std::vector<uint8_t> data;
    data.push_back(0x16);  // content type: Handshake
    data.push_back(0x03); data.push_back(0x01);  // version: TLS 1.0
    uint16_t recordLen = static_cast<uint16_t>(handshake.size());
    data.push_back(static_cast<uint8_t>(recordLen >> 8));
    data.push_back(static_cast<uint8_t>(recordLen & 0xFF));
    data.insert(data.end(), handshake.begin(), handshake.end());

    size_t offset = 0;
    auto result = fdpi::decodeTls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->contentType, 22);  // Handshake
    EXPECT_EQ(result->version, 0x0301);  // TLS 1.0 record version
    EXPECT_TRUE(result->sni.has_value());
    EXPECT_EQ(result->sni.value(), "example.com");
    ASSERT_EQ(result->cipherSuites.size(), 2u);
    EXPECT_EQ(result->cipherSuites[0], 0x1301);
    EXPECT_EQ(result->cipherSuites[1], 0x1302);
}

TEST(TlsDecoder, ParsesClientHelloWithALPN) {
    // Build a ClientHello with ALPN extension
    std::vector<uint8_t> extensions;

    // ALPN extension (type=0x0010)
    std::string proto1 = "h2";
    std::string proto2 = "http/1.1";
    uint16_t alpnListLen = static_cast<uint16_t>(1 + proto1.size() + 1 + proto2.size());
    uint16_t alpnExtDataLen = static_cast<uint16_t>(alpnListLen + 2);

    extensions.push_back(0x00); extensions.push_back(0x10);  // ALPN extension type
    extensions.push_back(static_cast<uint8_t>(alpnExtDataLen >> 8));
    extensions.push_back(static_cast<uint8_t>(alpnExtDataLen & 0xFF));
    extensions.push_back(static_cast<uint8_t>(alpnListLen >> 8));
    extensions.push_back(static_cast<uint8_t>(alpnListLen & 0xFF));
    extensions.push_back(static_cast<uint8_t>(proto1.size()));
    for (char c : proto1) extensions.push_back(static_cast<uint8_t>(c));
    extensions.push_back(static_cast<uint8_t>(proto2.size()));
    for (char c : proto2) extensions.push_back(static_cast<uint8_t>(c));

    // Build ClientHello
    std::vector<uint8_t> clientHello;
    clientHello.push_back(0x03); clientHello.push_back(0x03);  // TLS 1.2
    for (int i = 0; i < 32; ++i) clientHello.push_back(0x00);  // random
    clientHello.push_back(0x00);  // session ID length
    clientHello.push_back(0x00); clientHello.push_back(0x02);  // cipher suites length
    clientHello.push_back(0xC0); clientHello.push_back(0x2F);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    clientHello.push_back(0x01); clientHello.push_back(0x00);  // compression
    uint16_t extLen = static_cast<uint16_t>(extensions.size());
    clientHello.push_back(static_cast<uint8_t>(extLen >> 8));
    clientHello.push_back(static_cast<uint8_t>(extLen & 0xFF));
    clientHello.insert(clientHello.end(), extensions.begin(), extensions.end());

    // Build Handshake + Record
    std::vector<uint8_t> data;
    data.push_back(0x16);
    data.push_back(0x03); data.push_back(0x01);
    uint16_t totalLen = static_cast<uint16_t>(clientHello.size() + 4);
    data.push_back(static_cast<uint8_t>(totalLen >> 8));
    data.push_back(static_cast<uint8_t>(totalLen & 0xFF));
    data.push_back(0x01);  // ClientHello type
    uint32_t chLen = static_cast<uint32_t>(clientHello.size());
    data.push_back(static_cast<uint8_t>((chLen >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((chLen >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(chLen & 0xFF));
    data.insert(data.end(), clientHello.begin(), clientHello.end());

    size_t offset = 0;
    auto result = fdpi::decodeTls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->alpn.has_value());
    ASSERT_EQ(result->alpn->size(), 2u);
    EXPECT_EQ((*result->alpn)[0], "h2");
    EXPECT_EQ((*result->alpn)[1], "http/1.1");
}

TEST(TlsDecoder, ParsesClientHelloWithSupportedVersions) {
    // Build ClientHello with supported_versions extension (type=0x002B)
    std::vector<uint8_t> extensions;

    // supported_versions extension
    extensions.push_back(0x00); extensions.push_back(0x2B);  // type
    extensions.push_back(0x00); extensions.push_back(0x05);  // extension data length: 5
    extensions.push_back(0x04);  // supported versions list length: 4
    extensions.push_back(0x03); extensions.push_back(0x04);  // TLS 1.3
    extensions.push_back(0x03); extensions.push_back(0x03);  // TLS 1.2

    std::vector<uint8_t> clientHello;
    clientHello.push_back(0x03); clientHello.push_back(0x03);
    for (int i = 0; i < 32; ++i) clientHello.push_back(0x00);
    clientHello.push_back(0x00);
    clientHello.push_back(0x00); clientHello.push_back(0x02);
    clientHello.push_back(0x13); clientHello.push_back(0x01);
    clientHello.push_back(0x01); clientHello.push_back(0x00);
    uint16_t extLen = static_cast<uint16_t>(extensions.size());
    clientHello.push_back(static_cast<uint8_t>(extLen >> 8));
    clientHello.push_back(static_cast<uint8_t>(extLen & 0xFF));
    clientHello.insert(clientHello.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> data;
    data.push_back(0x16);
    data.push_back(0x03); data.push_back(0x01);
    uint16_t totalLen = static_cast<uint16_t>(clientHello.size() + 4);
    data.push_back(static_cast<uint8_t>(totalLen >> 8));
    data.push_back(static_cast<uint8_t>(totalLen & 0xFF));
    data.push_back(0x01);
    uint32_t chLen = static_cast<uint32_t>(clientHello.size());
    data.push_back(static_cast<uint8_t>((chLen >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((chLen >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(chLen & 0xFF));
    data.insert(data.end(), clientHello.begin(), clientHello.end());

    size_t offset = 0;
    auto result = fdpi::decodeTls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->tlsVersion.has_value());
    EXPECT_EQ(result->tlsVersion.value(), 0x0304);  // TLS 1.3
}

TEST(TlsDecoder, ParsesMinimalTlsRecord) {
    // A minimal TLS record (e.g., Application Data)
    std::vector<uint8_t> data = {
        0x17,        // content type: Application Data (23)
        0x03, 0x03,  // version: TLS 1.2
        0x00, 0x05,  // length: 5
        0x01, 0x02, 0x03, 0x04, 0x05  // encrypted payload
    };
    size_t offset = 0;
    auto result = fdpi::decodeTls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->contentType, 23);  // Application Data
    EXPECT_EQ(result->version, 0x0303);  // TLS 1.2
    EXPECT_FALSE(result->sni.has_value());
    EXPECT_FALSE(result->alpn.has_value());
}

TEST(TlsDecoder, ParsesNonHandshakeRecord) {
    // ChangeCipherSpec record
    std::vector<uint8_t> data = {
        0x14,        // content type: ChangeCipherSpec (20)
        0x03, 0x03,  // version: TLS 1.2
        0x00, 0x01,  // length: 1
        0x01         // payload
    };
    size_t offset = 0;
    auto result = fdpi::decodeTls(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->contentType, 20);
}

TEST(TlsDecoder, RejectsTruncatedRecord) {
    // Only 4 bytes - need at least 5 for TLS record header
    std::vector<uint8_t> data = {0x16, 0x03, 0x01, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeTls(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(TlsDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeTls(data, offset);
    ASSERT_FALSE(result.has_value());
}
