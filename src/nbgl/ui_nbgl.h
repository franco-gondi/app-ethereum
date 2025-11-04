#pragma once

#include "nbgl_use_case.h"
#include "shared_context.h"
#include "glyphs.h"

#ifdef SCREEN_SIZE_WALLET
#define ICON_APP_WARNING LARGE_WARNING_ICON
#define ICON_APP_REVIEW  LARGE_REVIEW_ICON
#if defined(TARGET_STAX)
#define ICON_LEDGER C_ledger_32px
#elif defined(TARGET_FLEX)
#define ICON_LEDGER C_ledger_40px
#else
#define ICON_LEDGER C_ledger_24px
#endif
#else
#define ICON_APP_WARNING WARNING_ICON
#define ICON_APP_REVIEW  REVIEW_ICON
#endif

const nbgl_icon_details_t* get_app_icon(bool caller_icon);
const nbgl_icon_details_t* get_tx_icon(bool fromPlugin);

// Global Warning struct for NBGL review flows
extern nbgl_warning_t warning;

void ui_idle(void);
void ui_settings(void);
