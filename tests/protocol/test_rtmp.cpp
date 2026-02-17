#include <gtest/gtest.h>

#include <fdpi/protocol/rtmp.hpp>

#include <vector>

TEST(RtmpDecoder, ParsesHandshake) {
    std::vector<uint8_t> data = {0x03}; // RTMP version 3
    size_t offset = 0;
    auto result = fdpi::decodeRtmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->isHandshake);
    EXPECT_EQ(result->handshakeType, 0);
    EXPECT_EQ(offset, 1u);
}

TEST(RtmpDecoder, ParsesChunkType0) {
    // Basic header: fmt=0 (00), csId=4 (000100) => 0x04
    // Use csId=4 to avoid handshake detection (0x03 at offset 0)
    // Message header type 0: 11 bytes
    std::vector<uint8_t> data = {
        0x04,                  // fmt=0, csId=4
        0x00, 0x00, 0x64,      // timestamp: 100
        0x00, 0x00, 0x0A,      // message length: 10
        0x14,                  // message type: Command (AMF0)
        0x01, 0x00, 0x00, 0x00 // message stream id: 1 (little-endian)
    };
    size_t offset = 0;
    auto result = fdpi::decodeRtmp(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isHandshake);
    EXPECT_EQ(result->chunkType, 0);
    EXPECT_EQ(result->chunkStreamId, 4u);
    EXPECT_EQ(result->timestamp, 100u);
    EXPECT_EQ(result->messageLength, 10u);
    EXPECT_EQ(result->messageTypeId, 0x14);
    EXPECT_EQ(result->messageStreamId, 1u);
}

TEST(RtmpDecoder, ParsesChunkType3) {
    // fmt=3 (11), csId=5 (000101) => 0xC5
    // No message header for type 3
    std::vector<uint8_t> data = {0xC5};
    size_t offset = 0;
    // Can't use offset=0 because first byte 0xC5 != 0x03 so not handshake
    // But offset != 0 is required to skip handshake check
    // Let's add a prefix byte
    std::vector<uint8_t> data2 = {0x00, 0xC5};
    offset = 1;
    auto result = fdpi::decodeRtmp(data2, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->chunkType, 3);
    EXPECT_EQ(result->chunkStreamId, 5u);
    EXPECT_EQ(offset, 2u);
}

TEST(RtmpDecoder, RejectsEmptyInput) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeRtmp(data, offset);
    ASSERT_FALSE(result.has_value());
}

TEST(RtmpDecoder, RejectsTruncatedChunkType0) {
    // fmt=0, csId=3, but only 5 bytes of message header (need 11)
    std::vector<uint8_t> data = {0x00, // prefix to avoid handshake
                                 0x03, // fmt=0, csId=3
                                 0x00, 0x00, 0x64, 0x00, 0x00};
    size_t offset = 1;
    auto result = fdpi::decodeRtmp(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}
