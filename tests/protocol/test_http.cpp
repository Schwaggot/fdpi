#include <gtest/gtest.h>
#include <fdpi/protocol/http.hpp>
#include <string>
#include <vector>

// Helper to convert string to byte vector
static std::vector<uint8_t> toBytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

TEST(HttpDecoder, ParsesGetRequest) {
    auto data = toBytes(
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: test/1.0\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isRequest);
    EXPECT_EQ(result->method, "GET");
    EXPECT_EQ(result->uri, "/");
    EXPECT_EQ(result->version, "1.1");
    EXPECT_EQ(result->statusCode, 0);
    ASSERT_GE(result->headers.size(), 2u);

    // Find Host header
    bool foundHost = false;
    for (const auto& [key, val] : result->headers) {
        if (key == "Host") {
            EXPECT_EQ(val, "example.com");
            foundHost = true;
        }
    }
    EXPECT_TRUE(foundHost);
}

TEST(HttpDecoder, ParsesPostRequest) {
    auto data = toBytes(
        "POST /api/data HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isRequest);
    EXPECT_EQ(result->method, "POST");
    EXPECT_EQ(result->uri, "/api/data");
    EXPECT_EQ(result->version, "1.1");
}

TEST(HttpDecoder, ParsesResponseWithStatus) {
    auto data = toBytes(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isRequest);
    EXPECT_EQ(result->statusCode, 200);
    EXPECT_EQ(result->version, "1.1");
    EXPECT_TRUE(result->method.empty());
}

TEST(HttpDecoder, ParsesResponse404) {
    auto data = toBytes(
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isRequest);
    EXPECT_EQ(result->statusCode, 404);
}

TEST(HttpDecoder, ParsesMultipleHeaders) {
    auto data = toBytes(
        "GET /path HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept: text/html\r\n"
        "Accept-Language: en-US\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_GE(result->headers.size(), 4u);
}

TEST(HttpDecoder, ParsesHTTP10) {
    auto data = toBytes(
        "GET / HTTP/1.0\r\n"
        "Host: old.example.com\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, "1.0");
}

TEST(HttpDecoder, ParsesHTTP10Response) {
    auto data = toBytes(
        "HTTP/1.0 301 Moved Permanently\r\n"
        "Location: https://example.com/\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, "1.0");
    EXPECT_EQ(result->statusCode, 301);
}

TEST(HttpDecoder, RejectsTruncatedRequest) {
    // Incomplete request line
    auto data = toBytes("GET / HT");
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(HttpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(HttpDecoder, ParsesGetWithQueryString) {
    auto data = toBytes(
        "GET /search?q=hello&lang=en HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->uri, "/search?q=hello&lang=en");
}

TEST(HttpDecoder, ParsesResponse500) {
    auto data = toBytes(
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
    );
    size_t offset = 0;
    auto result = fdpi::decodeHttp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->statusCode, 500);
}
