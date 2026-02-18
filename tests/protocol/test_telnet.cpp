#include <gtest/gtest.h>

#include <fdpi/protocol/telnet.hpp>

#include <vector>

TEST(TelnetDecoder, ParsesPlainTextData) {
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    size_t offset = 0;
    auto result = fdpi::decodeTelnet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->data, "Hello");
    EXPECT_TRUE(result->commands.empty());
    EXPECT_EQ(offset, 5u);
}

TEST(TelnetDecoder, ParsesIACCommand) {
    // IAC WILL ECHO, IAC DO SUPPRESS-GO-AHEAD
    std::vector<uint8_t> data = {
        0xFF, 0xFB, 0x01, // IAC WILL ECHO
        0xFF, 0xFD, 0x03, // IAC DO SUPPRESS-GO-AHEAD
    };
    size_t offset = 0;
    auto result = fdpi::decodeTelnet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->data.empty());
    ASSERT_EQ(result->commands.size(), 2u);
    EXPECT_EQ(result->commands[0].command, 0xFB); // WILL
    EXPECT_EQ(result->commands[0].option, 0x01);  // ECHO
    EXPECT_EQ(result->commands[1].command, 0xFD); // DO
    EXPECT_EQ(result->commands[1].option, 0x03);  // SUPPRESS-GO-AHEAD
    EXPECT_EQ(offset, 6u);
}

TEST(TelnetDecoder, ParsesMixedDataAndCommands) {
    // "Hi" + IAC WONT ECHO + "!"
    std::vector<uint8_t> data = {
        'H', 'i', 0xFF, 0xFC, 0x01, // IAC WONT ECHO
        '!',
    };
    size_t offset = 0;
    auto result = fdpi::decodeTelnet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->data, "Hi!");
    ASSERT_EQ(result->commands.size(), 1u);
    EXPECT_EQ(result->commands[0].command, 0xFC); // WONT
    EXPECT_EQ(result->commands[0].option, 0x01);  // ECHO
    EXPECT_EQ(offset, 6u);
}

TEST(TelnetDecoder, ParsesSubNegotiation) {
    // IAC SB <option=24> <data: 0x00, 'V', 'T', '1', '0', '0'> IAC SE
    std::vector<uint8_t> data = {
        0xFF, 0xFA, 0x18,                // IAC SB TERMINAL-TYPE
        0x00, 'V',  'T',  '1', '0', '0', // sub-negotiation data
        0xFF, 0xF0,                      // IAC SE
    };
    size_t offset = 0;
    auto result = fdpi::decodeTelnet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->data.empty());
    EXPECT_TRUE(result->commands.empty());
    EXPECT_EQ(offset, 11u);
}

TEST(TelnetDecoder, RejectsEmpty) {
    std::vector<uint8_t> data;
    size_t offset = 0;
    auto result = fdpi::decodeTelnet(data, offset);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), fdpi::Error::TruncatedHeader);
}

TEST(TelnetDecoder, HandlesNonZeroOffset) {
    // 3 bytes padding + "OK"
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 'O', 'K'};
    size_t offset = 3;
    auto result = fdpi::decodeTelnet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->data, "OK");
    EXPECT_EQ(offset, 5u);
}
