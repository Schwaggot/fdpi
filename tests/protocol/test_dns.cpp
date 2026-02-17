#include <fdpi/protocol/dns.hpp>
#include <gtest/gtest.h>
#include <vector>

// Helper to build DNS name in wire format (length-prefixed labels)
static std::vector<uint8_t> dnsName(const std::string& name) {
    std::vector<uint8_t> result;
    size_t pos = 0;
    while (pos < name.size()) {
        auto dot = name.find('.', pos);
        if (dot == std::string::npos)
            dot = name.size();
        result.push_back(static_cast<uint8_t>(dot - pos));
        for (size_t i = pos; i < dot; ++i)
            result.push_back(static_cast<uint8_t>(name[i]));
        pos = dot + 1;
    }
    result.push_back(0); // root label
    return result;
}

TEST(DnsDecoder, ParsesSimpleQuery) {
    // DNS query for example.com, type A, class IN
    auto qname = dnsName("example.com");

    std::vector<uint8_t> data = {
        0x12, 0x34, // ID: 0x1234
        0x01, 0x00, // Flags: standard query, RD=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    };
    // Append question name
    data.insert(data.end(), qname.begin(), qname.end());
    // Type A (1) and Class IN (1)
    data.push_back(0x00);
    data.push_back(0x01); // type: A
    data.push_back(0x00);
    data.push_back(0x01); // class: IN

    size_t offset = 0;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->id, 0x1234);
    EXPECT_FALSE(result->isResponse);
    EXPECT_EQ(result->opcode, 0);
    EXPECT_EQ(result->rcode, 0);
    EXPECT_TRUE(result->recursionDesired);
    EXPECT_FALSE(result->recursionAvailable);
    EXPECT_FALSE(result->authoritative);
    EXPECT_FALSE(result->truncated);
    ASSERT_EQ(result->questions.size(), 1u);
    EXPECT_EQ(result->questions[0].name, "example.com");
    EXPECT_EQ(result->questions[0].type, 1);   // A
    EXPECT_EQ(result->questions[0].qclass, 1); // IN
    EXPECT_TRUE(result->answers.empty());
}

TEST(DnsDecoder, ParsesResponseWithARecord) {
    // DNS response with one A record answer
    auto qname = dnsName("example.com");

    std::vector<uint8_t> data = {
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: response, RD=1, RA=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    };
    // Question section
    data.insert(data.end(), qname.begin(), qname.end());
    data.push_back(0x00);
    data.push_back(0x01); // type: A
    data.push_back(0x00);
    data.push_back(0x01); // class: IN

    // Answer section: example.com -> 93.184.216.34
    // Use name compression pointer: 0xC00C points to offset 12 (question name)
    data.push_back(0xC0);
    data.push_back(0x0C); // name pointer
    data.push_back(0x00);
    data.push_back(0x01); // type: A
    data.push_back(0x00);
    data.push_back(0x01); // class: IN
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x01);
    data.push_back(0x2C); // TTL: 300
    data.push_back(0x00);
    data.push_back(0x04); // RDLENGTH: 4
    data.push_back(0x5D);
    data.push_back(0xB8);
    data.push_back(0xD8);
    data.push_back(0x22); // RDATA: 93.184.216.34

    size_t offset = 0;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_TRUE(result->recursionDesired);
    EXPECT_TRUE(result->recursionAvailable);
    EXPECT_EQ(result->rcode, 0);
    ASSERT_EQ(result->answers.size(), 1u);
    EXPECT_EQ(result->answers[0].type, 1);   // A
    EXPECT_EQ(result->answers[0].rclass, 1); // IN
    EXPECT_EQ(result->answers[0].ttl, 300u);
    ASSERT_EQ(result->answers[0].rdata.size(), 4u);
    EXPECT_EQ(result->answers[0].rdata[0], 0x5D);
    EXPECT_EQ(result->answers[0].rdata[1], 0xB8);
    EXPECT_EQ(result->answers[0].rdata[2], 0xD8);
    EXPECT_EQ(result->answers[0].rdata[3], 0x22);
}

TEST(DnsDecoder, ParsesAAAARecord) {
    auto qname = dnsName("example.com");

    std::vector<uint8_t> data = {
        0xAB, 0xCD, 0x81, 0x80, // response, RD=1, RA=1
        0x00, 0x01,             // QDCOUNT: 1
        0x00, 0x01,             // ANCOUNT: 1
        0x00, 0x00, 0x00, 0x00,
    };
    data.insert(data.end(), qname.begin(), qname.end());
    data.push_back(0x00);
    data.push_back(0x1C); // type: AAAA (28)
    data.push_back(0x00);
    data.push_back(0x01); // class: IN

    // Answer: AAAA record
    data.push_back(0xC0);
    data.push_back(0x0C); // name pointer
    data.push_back(0x00);
    data.push_back(0x1C); // type: AAAA
    data.push_back(0x00);
    data.push_back(0x01); // class: IN
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0x3C); // TTL: 60
    data.push_back(0x00);
    data.push_back(0x10); // RDLENGTH: 16
    // IPv6 address: 2606:2800:220:1:248:1893:25c8:1946
    data.insert(data.end(), {0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48,
                             0x18, 0x93, 0x25, 0xc8, 0x19, 0x46});

    size_t offset = 0;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->answers.size(), 1u);
    EXPECT_EQ(result->answers[0].type, 28); // AAAA
    EXPECT_EQ(result->answers[0].rdata.size(), 16u);
}

TEST(DnsDecoder, ParsesMultipleQuestions) {
    auto qname1 = dnsName("example.com");
    auto qname2 = dnsName("test.org");

    std::vector<uint8_t> data = {
        0x00, 0x01, 0x01, 0x00, // standard query, RD=1
        0x00, 0x02,             // QDCOUNT: 2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    // First question
    data.insert(data.end(), qname1.begin(), qname1.end());
    data.push_back(0x00);
    data.push_back(0x01); // type: A
    data.push_back(0x00);
    data.push_back(0x01); // class: IN
    // Second question
    data.insert(data.end(), qname2.begin(), qname2.end());
    data.push_back(0x00);
    data.push_back(0x1C); // type: AAAA
    data.push_back(0x00);
    data.push_back(0x01); // class: IN

    size_t offset = 0;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->questions.size(), 2u);
    EXPECT_EQ(result->questions[0].name, "example.com");
    EXPECT_EQ(result->questions[0].type, 1);
    EXPECT_EQ(result->questions[1].name, "test.org");
    EXPECT_EQ(result->questions[1].type, 28);
}

TEST(DnsDecoder, ParsesNXDOMAINResponse) {
    auto qname = dnsName("nonexistent.example.com");

    std::vector<uint8_t> data = {
        0x56, 0x78, 0x81, 0x83, // response, RD=1, RA=1, RCODE=NXDOMAIN (3)
        0x00, 0x01,             // QDCOUNT: 1
        0x00, 0x00,             // ANCOUNT: 0
        0x00, 0x00, 0x00, 0x00,
    };
    data.insert(data.end(), qname.begin(), qname.end());
    data.push_back(0x00);
    data.push_back(0x01); // type: A
    data.push_back(0x00);
    data.push_back(0x01); // class: IN

    size_t offset = 0;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isResponse);
    EXPECT_EQ(result->rcode, 3); // NXDOMAIN
    EXPECT_TRUE(result->answers.empty());
}

TEST(DnsDecoder, ParsesAuthoritativeResponse) {
    auto qname = dnsName("example.com");

    std::vector<uint8_t> data = {
        0x00, 0x01, 0x85, 0x00, // response, AA=1, RD=1
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    data.insert(data.end(), qname.begin(), qname.end());
    data.push_back(0x00);
    data.push_back(0x01);
    data.push_back(0x00);
    data.push_back(0x01);

    size_t offset = 0;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->authoritative);
}

TEST(DnsDecoder, RejectsTruncatedMessage) {
    // Only 11 bytes - DNS header is 12 bytes
    std::vector<uint8_t> data = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
                                 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t offset = 0;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(DnsDecoder, DecodesWithTcpLengthPrefixOffset) {
    // Simulate DNS over TCP: 2-byte length prefix followed by DNS message
    auto qname = dnsName("example.com");

    std::vector<uint8_t> data = {
        0x00, 0x1D, // TCP length prefix (29 bytes)
        0x12, 0x34, // ID: 0x1234
        0x01, 0x00, // Flags: standard query, RD=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    };
    data.insert(data.end(), qname.begin(), qname.end());
    data.push_back(0x00);
    data.push_back(0x01); // type: A
    data.push_back(0x00);
    data.push_back(0x01); // class: IN

    // Decode starting at offset 2 (skipping TCP length prefix)
    size_t offset = 2;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->id, 0x1234);
    EXPECT_FALSE(result->isResponse);
    EXPECT_TRUE(result->recursionDesired);
    ASSERT_EQ(result->questions.size(), 1u);
    EXPECT_EQ(result->questions[0].name, "example.com");
    EXPECT_EQ(result->questions[0].type, 1);
}

TEST(DnsDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeDns(data, offset);
    ASSERT_FALSE(result.has_value());
}
