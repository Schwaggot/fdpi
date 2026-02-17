#include <gtest/gtest.h>

#include <fdpi/protocol/ssdp.hpp>

#include <vector>

TEST(SsdpDecoder, ParsesMSearchRequest) {
    std::string raw = "M-SEARCH * HTTP/1.1\r\n"
                      "HOST: 239.255.255.250:1900\r\n"
                      "MAN: \"ssdp:discover\"\r\n"
                      "ST: ssdp:all\r\n"
                      "\r\n";
    std::vector<uint8_t> data(raw.begin(), raw.end());
    size_t offset = 0;
    auto result = fdpi::decodeSsdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isRequest);
    EXPECT_EQ(result->method, "M-SEARCH");
    EXPECT_EQ(result->uri, "*");
    EXPECT_EQ(result->headers.size(), 3u);
    EXPECT_EQ(result->headers[0].first, "HOST");
    EXPECT_EQ(result->headers[0].second, "239.255.255.250:1900");
}

TEST(SsdpDecoder, ParsesNotifyRequest) {
    std::string raw = "NOTIFY * HTTP/1.1\r\n"
                      "HOST: 239.255.255.250:1900\r\n"
                      "NT: upnp:rootdevice\r\n"
                      "NTS: ssdp:alive\r\n"
                      "\r\n";
    std::vector<uint8_t> data(raw.begin(), raw.end());
    size_t offset = 0;
    auto result = fdpi::decodeSsdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isRequest);
    EXPECT_EQ(result->method, "NOTIFY");
}

TEST(SsdpDecoder, ParsesResponse) {
    std::string raw = "HTTP/1.1 200 OK\r\n"
                      "CACHE-CONTROL: max-age=1800\r\n"
                      "ST: upnp:rootdevice\r\n"
                      "\r\n";
    std::vector<uint8_t> data(raw.begin(), raw.end());
    size_t offset = 0;
    auto result = fdpi::decodeSsdp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isRequest);
    EXPECT_EQ(result->statusCode, 200);
}

TEST(SsdpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeSsdp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(SsdpDecoder, RejectsMalformedPacket) {
    std::string raw = "garbage data without line ending";
    std::vector<uint8_t> data(raw.begin(), raw.end());
    size_t offset = 0;
    auto result = fdpi::decodeSsdp(data, offset);
    ASSERT_FALSE(result.has_value());
}
