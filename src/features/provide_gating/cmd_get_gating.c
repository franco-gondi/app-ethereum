/*******************************************************************************
 *   Ledger Ethereum App
 *   (c) 2025 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ********************************************************************************/

#ifdef HAVE_GATING_SUPPORT

#include "cmd_get_gating.h"
#include "apdu_constants.h"
#include "hash_bytes.h"
#include "public_keys.h"
#include "getPublicKey.h"
#include "tlv.h"
#include "tlv_apdu.h"
#include "utils.h"
#include "nbgl_use_case.h"
#include "os_pki.h"
#include "network.h"
#include "ui_callbacks.h"
#include "ui_nbgl.h"
#include "common_utils.h"
#include "plugin_utils.h"
#include "mem_utils.h"

#define TYPE_GATED_SIGNING 0x0D
#define STRUCT_VERSION     0x01

#define GATING_MSG_SIZE 100
#define GATING_URL_SIZE 30

enum {
    TAG_STRUCTURE_TYPE = 0x01,
    TAG_STRUCTURE_VERSION = 0x02,
    TAG_ADDRESS = 0x22,
    TAG_CHAIN_ID = 0x23,
    TAG_SELECTOR = 0x40,
    TAG_INTRO_MSG = 0x82,
    TAG_TINY_URL = 0x83,
    TAG_DER_SIGNATURE = 0x15,
};

enum {
    BIT_STRUCTURE_TYPE,
    BIT_STRUCTURE_VERSION,
    BIT_ADDRESS,
    BIT_CHAIN_ID,
    BIT_SELECTOR,
    BIT_INTRO_MSG,
    BIT_TINY_URL,
    BIT_DER_SIGNATURE,
};

typedef struct gating_s {
    uint64_t chain_id;
    const char selector[SELECTOR_SIZE];
    const char intro_msg[GATING_MSG_SIZE + 1];  // +1 for the null terminator
    const char tiny_url[GATING_URL_SIZE + 1];   // +1 for the null terminator
    const char addr[ADDRESS_LENGTH];
} gating_t;

typedef struct {
    gating_t *gating;
    uint8_t sig_size;
    uint8_t *sig;
    cx_sha256_t hash_ctx;
    uint32_t rcv_flags;
} s_gating_ctx;

// Global structure to store the tx gating parameters
static gating_t *GATING = NULL;
static nbgl_preludeDetails_t prelude_details = {0};
static nbgl_genericDetails_t generic_details = {0};

// Macros to check the field length
#define CHECK_FIELD_LENGTH(tag, len, expected)  \
    do {                                        \
        if (len != expected) {                  \
            PRINTF("%s Size mismatch!\n", tag); \
            return SWO_INCORRECT_DATA;          \
        }                                       \
    } while (0)
#define CHECK_FIELD_OVERFLOW(tag, field, len)   \
    do {                                        \
        if (len >= sizeof(field)) {             \
            PRINTF("%s Size overflow!\n", tag); \
            return SWO_INSUFFICIENT_MEMORY;     \
        }                                       \
    } while (0)

// Macro to check the field value
#define CHECK_FIELD_VALUE(tag, value, expected)  \
    do {                                         \
        if (value != expected) {                 \
            PRINTF("%s Value mismatch!\n", tag); \
            return SWO_INCORRECT_DATA;           \
        }                                        \
    } while (0)

// Macro to check the field value
#define CHECK_EMPTY_BUFFER(tag, field, len)   \
    do {                                      \
        if (memcmp(field, empty, len) == 0) { \
            PRINTF("%s Zero buffer!\n", tag); \
            return SWO_INCORRECT_DATA;        \
        }                                     \
    } while (0)

// Macro to copy the field
#define COPY_FIELD(field, data)                             \
    do {                                                    \
        memmove((void *) field, data->value, data->length); \
    } while (0)

/**
 * @brief Parse the STRUCTURE_TYPE value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static uint16_t parse_struct_type(const s_tlv_data *data, s_gating_ctx *context) {
    CHECK_FIELD_LENGTH("STRUCTURE_TYPE", data->length, 1);
    CHECK_FIELD_VALUE("STRUCTURE_TYPE", data->value[0], TYPE_GATED_SIGNING);
    context->rcv_flags |= SET_BIT(BIT_STRUCTURE_TYPE);
    return SWO_SUCCESS;
}

/**
 * @brief Parse the STRUCTURE_VERSION value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static uint16_t parse_struct_version(const s_tlv_data *data, s_gating_ctx *context) {
    CHECK_FIELD_LENGTH("STRUCTURE_VERSION", data->length, 1);
    CHECK_FIELD_VALUE("STRUCTURE_VERSION", data->value[0], STRUCT_VERSION);
    context->rcv_flags |= SET_BIT(BIT_STRUCTURE_VERSION);
    return SWO_SUCCESS;
}

/**
 * @brief Parse the SELECTOR value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static uint16_t parse_selector(const s_tlv_data *data, s_gating_ctx *context) {
    uint8_t empty[SELECTOR_SIZE] = {0};
    CHECK_FIELD_LENGTH("SELECTOR", data->length, SELECTOR_SIZE);
    CHECK_EMPTY_BUFFER("SELECTOR", data->value, data->length);
    COPY_FIELD(context->gating->selector, data);
    context->rcv_flags |= SET_BIT(BIT_SELECTOR);
    return SWO_SUCCESS;
}

/**
 * @brief Parse the ADDRESS value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static uint16_t parse_address(const s_tlv_data *data, s_gating_ctx *context) {
    uint8_t empty[ADDRESS_LENGTH] = {0};
    CHECK_FIELD_LENGTH("ADDRESS", data->length, ADDRESS_LENGTH);
    CHECK_EMPTY_BUFFER("ADDRESS", data->value, data->length);
    COPY_FIELD(context->gating->addr, data);
    context->rcv_flags |= SET_BIT(BIT_ADDRESS);
    return SWO_SUCCESS;
}

/**
 * @brief Parse the CHAIN_ID value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static uint16_t parse_chain_id(const s_tlv_data *data, s_gating_ctx *context) {
    uint64_t chain_id;
    uint64_t max_range;

    CHECK_FIELD_LENGTH("CHAIN_ID", data->length, sizeof(uint64_t));
    // Check if the chain ID is supported
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2294.md
    max_range = 0x7FFFFFFFFFFFFFDB;
    chain_id = u64_from_BE(data->value, data->length);
    // Check if the chain_id is supported
    if ((chain_id > max_range) || (chain_id == 0)) {
        PRINTF("Unsupported chain ID: %u\n", chain_id);
        return SWO_INCORRECT_DATA;
    }

    context->gating->chain_id = chain_id;
    context->rcv_flags |= SET_BIT(BIT_CHAIN_ID);
    return SWO_SUCCESS;
}

/**
 * @brief Parse the INTRO_MSG value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static uint16_t parse_intro_msg(const s_tlv_data *data, s_gating_ctx *context) {
    CHECK_FIELD_OVERFLOW("INTRO_MSG", context->gating->intro_msg, data->length);
    // Check if the name is printable
    if (!check_name(data->value, data->length)) {
        PRINTF("INTRO_MSG is not printable!\n");
        return SWO_INCORRECT_DATA;
    }
    COPY_FIELD(context->gating->intro_msg, data);
    context->rcv_flags |= SET_BIT(BIT_INTRO_MSG);
    return SWO_SUCCESS;
}

/**
 * @brief Parse the TINY_URL value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static uint16_t parse_tiny_url(const s_tlv_data *data, s_gating_ctx *context) {
    CHECK_FIELD_OVERFLOW("TINY_URL", context->gating->tiny_url, data->length);
    // Check if the name is printable
    if (!check_name(data->value, data->length)) {
        PRINTF("TINY_URL is not printable!\n");
        return SWO_INCORRECT_DATA;
    }
    COPY_FIELD(context->gating->tiny_url, data);
    context->rcv_flags |= SET_BIT(BIT_TINY_URL);
    return SWO_SUCCESS;
}

/**
 * @brief Parse the SIGNATURE value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static uint16_t parse_signature(const s_tlv_data *data, s_gating_ctx *context) {
    context->sig_size = data->length;
    context->sig = (uint8_t *) data->value;
    context->rcv_flags |= SET_BIT(BIT_DER_SIGNATURE);
    return SWO_SUCCESS;
}

/**
 * @brief Verify the payload signature
 *
 * Verify the SHA-256 hash of the payload against the public key
 *
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool verify_signature(s_gating_ctx *context) {
    uint8_t hash[INT256_LENGTH];
    cx_err_t error = CX_INTERNAL_ERROR;
    bool ret_code = false;

    CX_CHECK(
        cx_hash_no_throw((cx_hash_t *) &context->hash_ctx, CX_LAST, NULL, 0, hash, INT256_LENGTH));

    CX_CHECK(check_signature_with_pubkey("Gating Signing",
                                         hash,
                                         sizeof(hash),
                                         NULL,
                                         0,
                                         CERTIFICATE_PUBLIC_KEY_USAGE_GATED_SIGNING,
                                         (uint8_t *) (context->sig),
                                         context->sig_size));

    ret_code = true;
end:
    return ret_code;
}

/**
 * @brief Verify the received fields
 *
 * Check the mandatory fields are present
 *
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool verify_fields(s_gating_ctx *context) {
    uint32_t expected_fields;

    expected_fields = (1 << BIT_STRUCTURE_TYPE) | (1 << BIT_STRUCTURE_VERSION) |
                      (1 << BIT_CHAIN_ID) | (1 << BIT_ADDRESS) | (1 << BIT_INTRO_MSG) |
                      (1 << BIT_TINY_URL) | (1 << BIT_DER_SIGNATURE);

    return ((context->rcv_flags & expected_fields) == expected_fields);
}

/**
 * @brief Print the gating parameters.
 *
 * @param[in] context Gating context
 * Only for debug purpose.
 */
static void print_gating_info(s_gating_ctx *context) {
    char chain_str[sizeof(uint64_t) * 2 + 1] = {0};

    PRINTF("****************************************************************************\n");
    PRINTF("[GATING] - Retrieved Gating descriptor:\n");
    PRINTF("[GATING] -    Address: %.*h\n", ADDRESS_LENGTH, context->gating->addr);
    if (context->gating->chain_id != 0) {
        u64_to_string(context->gating->chain_id, chain_str, sizeof(chain_str));
        PRINTF("[GATING] -    ChainID: %s\n", chain_str);
    }
    if (allzeroes((const void *) context->gating->selector, SELECTOR_SIZE) == 0) {
        PRINTF("[GATING] -    Selector: %.*h\n", SELECTOR_SIZE, context->gating->selector);
    }
    PRINTF("[GATING] -    Intro Msg: %s\n", context->gating->intro_msg);
    PRINTF("[GATING] -    Tiny URL: %s\n", context->gating->tiny_url);
}

/**
 * @brief Parse the received TLV.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return APDU Response code
 */
static bool handle_gating_tlv(const s_tlv_data *data, s_gating_ctx *context) {
    uint16_t sw = SWO_PARAMETER_ERROR_NO_INFO;

    switch (data->tag) {
        case TAG_STRUCTURE_TYPE:
            sw = parse_struct_type(data, context);
            break;
        case TAG_STRUCTURE_VERSION:
            sw = parse_struct_version(data, context);
            break;
        case TAG_CHAIN_ID:
            sw = parse_chain_id(data, context);
            break;
        case TAG_ADDRESS:
            sw = parse_address(data, context);
            break;
        case TAG_SELECTOR:
            sw = parse_selector(data, context);
            break;
        case TAG_INTRO_MSG:
            sw = parse_intro_msg(data, context);
            break;
        case TAG_TINY_URL:
            sw = parse_tiny_url(data, context);
            break;
        case TAG_DER_SIGNATURE:
            sw = parse_signature(data, context);
            break;
        default:
            PRINTF(TLV_TAG_ERROR_MSG, data->tag);
            sw = SWO_SUCCESS;
            break;
    }
    if ((sw == SWO_SUCCESS) && (data->tag != TAG_DER_SIGNATURE)) {
        hash_nbytes(data->raw, data->raw_size, (cx_hash_t *) &context->hash_ctx);
    }
    return (sw == SWO_SUCCESS);
}

/**
 * @brief Parse the TLV payload containing the TX Gating parameters.
 *
 * @param[in] payload buffer received
 * @param[in] size of the buffer
 * @return whether the TLV payload was handled successfully or not
 */
static bool handle_tlv_payload(const uint8_t *payload, uint16_t size) {
    bool parsing_ret;
    s_gating_ctx ctx = {0};

    if (mem_buffer_allocate((void **) &GATING, sizeof(gating_t)) == false) {
        PRINTF("Error: Not enough memory!\n");
        return false;
    }
    ctx.gating = GATING;

    // Reset the structures
    explicit_bzero(GATING, sizeof(gating_t));
    // Initialize the hash context
    cx_sha256_init(&ctx.hash_ctx);

    parsing_ret = tlv_parse(payload, size, (f_tlv_data_handler) &handle_gating_tlv, &ctx);
    if (!parsing_ret || !verify_fields(&ctx) || !verify_signature(&ctx)) {
        explicit_bzero(GATING, sizeof(gating_t));
        explicit_bzero(&ctx, sizeof(s_gating_ctx));
        return false;
    }
    print_gating_info(&ctx);
    return true;
}

/**
 * @brief Handle Gating APDU.
 *
 * @param[in] p1 APDU parameter 1 (indicates Data payload or Opt-In request)
 * @param[in] p2 APDU parameter 2 (indicates if the payload is the first chunk)
 * @param[in] data buffer received
 * @param[in] length of the buffer
 * @return APDU Response code
 */
uint16_t handle_gating(uint8_t p1, uint8_t p2, const uint8_t *data, uint8_t length) {
    uint16_t sw = SWO_PARAMETER_ERROR_NO_INFO;

    switch (p2) {
        case 0x00:
            if (!tlv_from_apdu(p1 == P1_FIRST_CHUNK, length, data, &handle_tlv_payload)) {
                sw = SWO_INCORRECT_DATA;
            } else {
                sw = SWO_SUCCESS;
            }
            break;
        default:
            PRINTF("Error: Unexpected P1 (%u)!\n", p1);
            sw = SWO_WRONG_P1_P2;
            break;
    }
    return sw;
}

/**
 * @brief Clear the Gating parameters.
 *
 */
void clear_gating(void) {
    mem_buffer_cleanup((void **) &GATING);
}

/**
 * @brief Check the FROM_ADDRESS vs Gating payload.
 *
 * @return whether it was successful
 */
static bool check_gating_from_address(void) {
    uint8_t msg_sender[ADDRESS_LENGTH] = {0};
    if (get_public_key(msg_sender, sizeof(msg_sender)) != SWO_SUCCESS) {
        PRINTF("[GATING] Unable to get the public key!\n");
        return false;
    }
    if (memcmp(GATING->addr, msg_sender, ADDRESS_LENGTH) != 0) {
        PRINTF("[GATING] FROM addr mismatch: %.*h != %.*h\n",
               ADDRESS_LENGTH,
               GATING->addr,
               ADDRESS_LENGTH,
               msg_sender);
        return false;
    }
    return true;
}

/**
 * @brief Check the CHAIN_ID vs Gating payload.
 *
 * @return whether it was successful
 */
static bool check_gating_chain_id(void) {
    uint64_t chain_id = get_tx_chain_id();
    // Check Chain_ID in case of a standard transaction (No EIP191, No EIP712)
    if ((appState == APP_STATE_SIGNING_TX) && (GATING->chain_id != chain_id)) {
        PRINTF("[GATING] Chain_ID mismatch: %u != %u\n", GATING->chain_id, chain_id);
        return false;
    }
    return true;
}

/**
 * @brief Check the SELECTOR vs Gating payload.
 *
 * @return whether it was successful
 */
static bool check_gating_selector(void) {
    if (memcmp(GATING->selector, dataContext.tokenContext.data, SELECTOR_SIZE) != 0) {
        PRINTF("[GATING] SELECTOR mismatch: %.*h != %.*h\n",
               SELECTOR_SIZE,
               GATING->selector,
               SELECTOR_SIZE,
               dataContext.tokenContext.data);
        return false;
    }
    return true;
}

/**
 * @brief Check the TX vs Gating parameters (CHAIN_ID, TX_HASH).
 *
 * @param[in] fromPlugin If true, the data is coming from a plugin, otherwise it is a standard
 * transaction
 * @return whether it was successful
 */
static bool check_tx_gating_params(bool fromPlugin) {
    if (check_gating_chain_id() == false) {
        return false;
    }
    if (check_gating_from_address() == false) {
        return false;
    }
    if (fromPlugin) {
        if (check_gating_selector() == false) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Configure the warning prelude set for the NBGL review flows.
 *
 * @param[in] fromPlugin If true, the data is coming from a plugin, otherwise it is a standard
 * transaction
 * @return whether the descriptor corresponds to the current transaction
 */
bool set_gating_warning(bool fromPlugin) {
    // Check if the descriptor is set
    if ((GATING == NULL) || (allzeroes((const void *) GATING->addr, ADDRESS_LENGTH))) {
        PRINTF("[GATING] Descriptor not received\n");
        return true;
    }

    // Gated signing received => Verify parameters of the Transaction
    if (!check_tx_gating_params(fromPlugin)) {
        PRINTF("[GATING] Parameters mismatch\n");
        return false;
    }
    // Gated signing valid => Adapt the UI screens
    explicit_bzero(&prelude_details, sizeof(prelude_details));
    explicit_bzero(&generic_details, sizeof(generic_details));

    generic_details.title = "Discover safer signing";
    generic_details.type = QRCODE_WARNING;
    generic_details.qrCode.url = GATING->tiny_url;
    generic_details.qrCode.text1 = GATING->tiny_url;
    generic_details.qrCode.text2 = "Discover a safer way to sign your transactions";
    generic_details.qrCode.centered = true;

    prelude_details.icon = &ICON_LEDGER;
    prelude_details.title = "There is a safer\nway to sign";
    prelude_details.description = GATING->intro_msg;
    prelude_details.buttonText = "Learn more";
    prelude_details.footerText = "Continue to blind signing";
    prelude_details.details = &generic_details;

    warning.prelude = &prelude_details;
    return true;
}

#endif  // HAVE_GATING_SUPPORT
