#include <gtest/gtest.h>

#include <fdpi/protocol/tftp.hpp>

#include <vector>

TEST(TftpDecoder, ParsesReadRequest) {
    // Opcode 1 (RRQ) + "test.txt\0" + "octet\0"
    std::vector<uint8_t> data = {
        0x00, 0x01,                                      // opcode = RRQ
        't',  'e',  's', 't', '.', 't',  'x', 't', 0x00, // filename
        'o',  'c',  't', 'e', 't', 0x00,                 // mode
    };
    size_t offset = 0;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 1);
    EXPECT_EQ(result->filename, "test.txt");
    EXPECT_EQ(result->mode, "octet");
    EXPECT_TRUE(result->options.empty());
    EXPECT_EQ(offset, data.size());
}

TEST(TftpDecoder, ParsesWriteRequest) {
    // Opcode 2 (WRQ) + "upload.bin\0" + "netascii\0"
    std::vector<uint8_t> data = {
        0x00, 0x02,                                                // opcode = WRQ
        'u',  'p',  'l', 'o', 'a', 'd', '.', 'b', 'i',  'n', 0x00, // filename
        'n',  'e',  't', 'a', 's', 'c', 'i', 'i', 0x00,            // mode
    };
    size_t offset = 0;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 2);
    EXPECT_EQ(result->filename, "upload.bin");
    EXPECT_EQ(result->mode, "netascii");
}

TEST(TftpDecoder, ParsesDataPacket) {
    // Opcode 3 (DATA) + block# 1 + data bytes
    std::vector<uint8_t> data = {
        0x00, 0x03,            // opcode = DATA
        0x00, 0x01,            // block number = 1
        0xDE, 0xAD, 0xBE, 0xEF // data
    };
    size_t offset = 0;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 3);
    EXPECT_EQ(result->blockNumber, 1);
    ASSERT_EQ(result->blockData.size(), 4u);
    EXPECT_EQ(result->blockData[0], 0xDE);
    EXPECT_EQ(result->blockData[3], 0xEF);
    EXPECT_EQ(offset, data.size());
}

TEST(TftpDecoder, ParsesAck) {
    // Opcode 4 (ACK) + block# 5
    std::vector<uint8_t> data = {
        0x00,
        0x04, // opcode = ACK
        0x00,
        0x05, // block number = 5
    };
    size_t offset = 0;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 4);
    EXPECT_EQ(result->blockNumber, 5);
    EXPECT_EQ(offset, 4u);
}

TEST(TftpDecoder, ParsesError) {
    // Opcode 5 (ERROR) + error code 1 + "File not found\0"
    std::vector<uint8_t> data = {
        0x00, 0x05, // opcode = ERROR
        0x00, 0x01, // error code = 1
        'F',  'i',  'l', 'e', ' ', 'n', 'o',  't',
        ' ',  'f',  'o', 'u', 'n', 'd', 0x00, // error message
    };
    size_t offset = 0;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 5);
    EXPECT_EQ(result->errorCode, 1);
    EXPECT_EQ(result->errorMessage, "File not found");
}

TEST(TftpDecoder, ParsesOptionsExtension) {
    // RRQ with RFC 2347 options: blksize=512, tsize=0
    std::vector<uint8_t> data = {
        0x00, 0x01,                                        // opcode = RRQ
        't',  'e',  's', 't',  '.', 't',  'x', 't',  0x00, // filename
        'o',  'c',  't', 'e',  't', 0x00,                  // mode
        'b',  'l',  'k', 's',  'i', 'z',  'e', 0x00,       // option name
        '5',  '1',  '2', 0x00,                             // option value
        't',  's',  'i', 'z',  'e', 0x00,                  // option name
        '0',  0x00,                                        // option value
    };
    size_t offset = 0;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 1);
    EXPECT_EQ(result->filename, "test.txt");
    EXPECT_EQ(result->mode, "octet");
    ASSERT_EQ(result->options.size(), 2u);
    EXPECT_EQ(result->options[0].first, "blksize");
    EXPECT_EQ(result->options[0].second, "512");
    EXPECT_EQ(result->options[1].first, "tsize");
    EXPECT_EQ(result->options[1].second, "0");
}

TEST(TftpDecoder, RejectsEmpty) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(TftpDecoder, RejectsTruncatedOpcode) {
    // Only 1 byte — need at least 2 for opcode
    std::vector<uint8_t> data = {0x00};
    size_t offset = 0;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(TftpDecoder, HandlesNonZeroOffset) {
    // 3 bytes padding + ACK block 1
    std::vector<uint8_t> data = {
        0xAA, 0xBB, 0xCC, // padding
        0x00, 0x04,       // opcode = ACK
        0x00, 0x01,       // block number = 1
    };
    size_t offset = 3;
    auto result = fdpi::decodeTftp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->opcode, 4);
    EXPECT_EQ(result->blockNumber, 1);
    EXPECT_EQ(offset, 7u);
}
