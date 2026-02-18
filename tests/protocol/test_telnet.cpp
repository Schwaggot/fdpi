#include <gtest/gtest.h>

#include <fdpi/protocol/telnet.hpp>

#include <vector>

TEST(TelnetDecoder, ParsesPlainTextData) {
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    size_t offset = 0;
    auto result = fdpi::decodeTelnet(data, offset);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->data.size(), 1u);
    EXPECT_EQ(result->data[0], "Hello");
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
    EXPECT_EQ(result->commands[0].command, 0xFB);
    EXPECT_EQ(result->commands[0].option, 0x01);
    EXPECT_EQ(result->commands[1].command, 0xFD);
    EXPECT_EQ(result->commands[1].option, 0x03);
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
    ASSERT_EQ(result->data.size(), 2u);
    EXPECT_EQ(result->data[0], "Hi");
    EXPECT_EQ(result->data[1], "!");
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
    ASSERT_EQ(result->commands.size(), 2u);
    EXPECT_EQ(result->commands[0].command, 0xFA); // SB
    EXPECT_EQ(result->commands[0].option, 0x18);  // TERMINAL-TYPE
    EXPECT_EQ(result->commands[1].command, 0xF0); // SE
    EXPECT_EQ(result->commands[1].option, 0x00);
    EXPECT_EQ(offset, 11u);
}

TEST(TelnetDecoder, ParsesTwoByteCommand) {
    // IAC IP (Interrupt Process = 0xF4) followed by IAC DO TTYPE
    std::vector<uint8_t> data = {
        0xFF, 0xF4,       // IAC IP
        0xFF, 0xFD, 0x18, // IAC DO TERMINAL-TYPE
    };
    size_t offset = 0;
    auto result = fdpi::decodeTelnet(data, offset);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->data.empty());
    ASSERT_EQ(result->commands.size(), 2u);
    EXPECT_EQ(result->commands[0].command, 0xF4); // IP
    EXPECT_EQ(result->commands[0].option, 0x00);
    EXPECT_EQ(result->commands[1].command, 0xFD); // DO
    EXPECT_EQ(result->commands[1].option, 0x18);  // TERMINAL-TYPE
    EXPECT_EQ(offset, 5u);
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
    ASSERT_EQ(result->data.size(), 1u);
    EXPECT_EQ(result->data[0], "OK");
    EXPECT_EQ(offset, 5u);
}
