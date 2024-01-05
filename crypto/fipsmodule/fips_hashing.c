// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/nid.h>

#include "digest/internal.h"
#include "delocate.h"

#include "../mem.c"
#include "../thread_pthread.c"
#include "../err/err.c"
#include "../../generated-src/err_data.c"

#include "hmac/hmac.c"
#include "evp/p_hmac.c"
#include "digest/digest.c"
#include "digest/digests.c"
#include "sha/sha256.c"
#include "service_indicator/service_indicator.c"
