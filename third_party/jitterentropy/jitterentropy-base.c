/*
 * Non-physical true random number generator based on timing jitter.
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2014 - 2021
 *
 * Design
 * ======
 *
 * See documentation in doc/ folder.
 *
 * Interface
 * =========
 *
 * See documentation in jitterentropy(3) man page.
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "jitterentropy.h"

#include "jitterentropy-base.h"
#include "jitterentropy-gcd.h"
#include "jitterentropy-health.h"
#include "jitterentropy-noise.h"
#include "jitterentropy-timer.h"
#include "jitterentropy-sha3.h"

#define MAJVERSION 3 /* API / ABI incompatible changes, functional changes that
		      * require consumer to be updated (as long as this number
		      * is zero, the API is not considered stable and can
		      * change without a bump of the major version) */
#define MINVERSION 1 /* API compatible, ABI may change, functional
		      * enhancements only, consumer can be left unchanged if
		      * enhancements are not considered */
#define PATCHLEVEL 0 /* API / ABI compatible, no functional changes, no
		      * enhancements, bug fixes only */

/***************************************************************************
 * Jitter RNG Static Definitions
 *
 * None of the following should be altered
 ***************************************************************************/

#ifdef __OPTIMIZE__
 #error "The CPU Jitter random number generator must not be compiled with optimizations. See documentation. Use the compiler switch -O0 for compiling jitterentropy.c."
#endif

/*
 * JENT_POWERUP_TESTLOOPCOUNT needs some loops to identify edge
 * systems. 100 is definitely too little.
 *
 * SP800-90B requires at least 1024 initial test cycles.
 */
#define JENT_POWERUP_TESTLOOPCOUNT 1024

/**
 * jent_version() - Return machine-usable version number of jent library
 *
 * The function returns a version number that is monotonic increasing
 * for newer versions. The version numbers are multiples of 100. For example,
 * version 1.2.3 is converted to 1020300 -- the last two digits are reserved
 * for future use.
 *
 * The result of this function can be used in comparing the version number
 * in a calling program if version-specific calls need to be make.
 *
 * @return Version number of jitterentropy library
 */
JENT_PRIVATE_STATIC
unsigned int jent_version(void)
{
	unsigned int version = 0;

	version =  MAJVERSION * 1000000;
	version += MINVERSION * 10000;
	version += PATCHLEVEL * 100;

	return version;
}

/***************************************************************************
 * Random Number Generation
 ***************************************************************************/

/**
 * Entry function: Obtain entropy for the caller.
 *
 * This function invokes the entropy gathering logic as often to generate
 * as many bytes as requested by the caller. The entropy gathering logic
 * creates 64 bit per invocation.
 *
 * This function truncates the last 64 bit entropy value output to the exact
 * size specified by the caller.
 *
 * @ec [in] Reference to entropy collector
 * @data [out] pointer to buffer for storing random data -- buffer must
 *	       already exist
 * @len [in] size of the buffer, specifying also the requested number of random
 *	     in bytes
 *
 * @return number of bytes returned when request is fulfilled or an error
 *
 * The following error codes can occur:
 *	-1	entropy_collector is NULL
 *	-2	RCT failed
 *	-3	APT test failed
 *	-4	The timer cannot be initialized
 *	-5	LAG failure
 */
JENT_PRIVATE_STATIC
ssize_t jent_read_entropy(struct rand_data *ec, char *data, size_t len)
{
	char *p = data;
	size_t orig_len = len;
	int ret = 0;

	if (NULL == ec)
		return -1;

	if (jent_notime_settick(ec))
		return -4;

	while (len > 0) {
		size_t tocopy;
		unsigned int health_test_result;

		jent_random_data(ec);

		if ((health_test_result = jent_health_failure(ec))) {
			if (health_test_result & JENT_RCT_FAILURE)
				ret = -2;
			else if (health_test_result & JENT_APT_FAILURE)
				ret = -3;
			else
				ret = -5;

			goto err;
		}

		if ((DATA_SIZE_BITS / 8) < len)
			tocopy = (DATA_SIZE_BITS / 8);
		else
			tocopy = len;

		jent_read_random_block(ec, p, tocopy);

		len -= tocopy;
		p += tocopy;
	}

	/*
	 * To be on the safe side, we generate one more round of entropy
	 * which we do not give out to the caller. That round shall ensure
	 * that in case the calling application crashes, memory dumps, pages
	 * out, or due to the CPU Jitter RNG lingering in memory for long
	 * time without being moved and an attacker cracks the application,
	 * all he reads in the entropy pool is a value that is NEVER EVER
	 * being used for anything. Thus, he does NOT see the previous value
	 * that was returned to the caller for cryptographic purposes.
	 */
	/*
	 * If we use secured memory, do not use that precaution as the secure
	 * memory protects the entropy pool. Moreover, note that using this
	 * call reduces the speed of the RNG by up to half
	 */
#ifndef CONFIG_CRYPTO_CPU_JITTERENTROPY_SECURE_MEMORY
	jent_random_data(ec);
#endif

err:
	jent_notime_unsettick(ec);
	return ret ? ret : (ssize_t)orig_len;
}

/**
 * Entry function: Obtain entropy for the caller.
 *
 * This is a service function to jent_read_entropy() with the difference
 * that it automatically re-allocates the entropy collector if a health
 * test failure is observed. Before reallocation, a new power-on health test
 * is performed. The allocation of the new entropy collector automatically
 * increases the OSR by one. This is done based on the idea that a health
 * test failure indicates that the assumed entropy rate is too high.
 *
 * Note the function returns with an health test error if the OSR is
 * getting too large. If an error is returned by this function, the Jitter RNG
 * is not safe to be used on the current system.
 *
 * @ec [in] Reference to entropy collector - this is a double pointer as
 *	    The entropy collector may be freed and reallocated.
 * @data [out] pointer to buffer for storing random data -- buffer must
 *	       already exist
 * @len [in] size of the buffer, specifying also the requested number of random
 *	     in bytes
 *
 * @return see jent_read_entropy()
 */
JENT_PRIVATE_STATIC
ssize_t jent_read_entropy_safe(struct rand_data **ec, char *data, size_t len)
{
	char *p = data;
	size_t orig_len = len;
	ssize_t ret = 0;

	if (!ec)
		return -1;

	while (len > 0) {
		unsigned int osr, flags;

		ret = jent_read_entropy(*ec, p, len);

		switch (ret) {
		case -1:
		case -4:
			return ret;
		case -2:
		case -3:
		case -5:
			osr = (*ec)->osr + 1;
			flags = (*ec)->flags;

			/* generic arbitrary cutoff */
			if (osr > 20)
				return ret;

			/* re-allocate entropy collector with higher OSR */
			jent_entropy_collector_free(*ec);

			/* Perform new health test */
			if (jent_entropy_init())
				return -1;

			*ec = jent_entropy_collector_alloc(osr, flags);
			if (!*ec)
				return -1;
			break;

		default:
			len -= (size_t)ret;
			p += (size_t)ret;
		}
	}

	return (ssize_t)orig_len;
}

/***************************************************************************
 * Initialization logic
 ***************************************************************************/

static struct rand_data
*jent_entropy_collector_alloc_internal(unsigned int osr,
				       unsigned int flags)
{
	struct rand_data *entropy_collector;

	/*
	 * Requesting disabling and forcing of internal timer
	 * makes no sense.
	 */
	if ((flags & JENT_DISABLE_INTERNAL_TIMER) &&
	    (flags & JENT_FORCE_INTERNAL_TIMER))
		return NULL;

	/*
	 * If the initial test code concludes to force the internal timer
	 * and the user requests it not to be used, do not allocate
	 * the Jitter RNG instance.
	 */
	if (jent_notime_forced() && (flags & JENT_DISABLE_INTERNAL_TIMER))
		return NULL;

	entropy_collector = jent_zalloc(sizeof(struct rand_data));
	if (NULL == entropy_collector)
		return NULL;

	if (!(flags & JENT_DISABLE_MEMORY_ACCESS)) {
		/* Allocate memory for adding variations based on memory
		 * access
		 */
		entropy_collector->mem = 
			(unsigned char *)jent_zalloc(JENT_MEMORY_SIZE);
		if (entropy_collector->mem == NULL)
			goto err;

		entropy_collector->memblocksize = JENT_MEMORY_BLOCKSIZE;
		entropy_collector->memblocks = JENT_MEMORY_BLOCKS;
		entropy_collector->memaccessloops = JENT_MEMORY_ACCESSLOOPS;
	}

	if (sha3_alloc(&entropy_collector->hash_state))
		goto err;

	/* Initialize the hash state */
	sha3_256_init(entropy_collector->hash_state);

	/* verify and set the oversampling rate */
	if (osr < JENT_MIN_OSR)
		osr = JENT_MIN_OSR;
	entropy_collector->osr = osr;
	entropy_collector->flags = flags;

	if (jent_fips_enabled() || (flags & JENT_FORCE_FIPS))
		entropy_collector->fips_enabled = 1;

	/* Initialize the APT */
	jent_apt_init(entropy_collector, osr);

	/* Initialize the Lag Predictor Test */
	jent_lag_init(entropy_collector, osr);

	/* Was jent_entropy_init run (establishing the common GCD)? */
	if (jent_gcd_get(&entropy_collector->jent_common_timer_gcd)) {
		/*
		 * It was not. This should probably be an error, but this
		 * behavior breaks the test code. Set the gcd to a value that
		 * won't hurt anything.
		 */
		entropy_collector->jent_common_timer_gcd = 1;
	}

	/* Use timer-less noise source */
	if (!(flags & JENT_DISABLE_INTERNAL_TIMER)) {
		if (jent_notime_enable(entropy_collector, flags))
			goto err;
	}

	return entropy_collector;

err:
	if (entropy_collector->mem != NULL)
		jent_zfree(entropy_collector->mem, JENT_MEMORY_SIZE);
	jent_zfree(entropy_collector, sizeof(struct rand_data));
	return NULL;
}

JENT_PRIVATE_STATIC
struct rand_data *jent_entropy_collector_alloc(unsigned int osr,
					       unsigned int flags)
{
	struct rand_data *ec = jent_entropy_collector_alloc_internal(osr,
								     flags);

	if (!ec)
		return ec;

	/* fill the data pad with non-zero values */
	if (jent_notime_settick(ec)) {
		jent_entropy_collector_free(ec);
		return NULL;
	}
	jent_random_data(ec);
	jent_notime_unsettick(ec);

	return ec;
}

JENT_PRIVATE_STATIC
void jent_entropy_collector_free(struct rand_data *entropy_collector)
{
	if (entropy_collector != NULL) {
		sha3_dealloc(entropy_collector->hash_state);
		jent_notime_disable(entropy_collector);
		if (entropy_collector->mem != NULL) {
			jent_zfree(entropy_collector->mem, JENT_MEMORY_SIZE);
			entropy_collector->mem = NULL;
		}
		jent_zfree(entropy_collector, sizeof(struct rand_data));
	}
}

int jent_time_entropy_init(unsigned int enable_notime)
{
	struct rand_data *ec;
	uint64_t *delta_history;
	int i, time_backwards = 0, count_stuck = 0, ret = 0;
	unsigned int health_test_result;

	delta_history = jent_gcd_init(JENT_POWERUP_TESTLOOPCOUNT);
	if (!delta_history)
		return EMEM;

	if (enable_notime)
		jent_notime_force();

	/*
	 * If the start-up health tests (including the APT and RCT) are not
	 * run, then the entropy source is not 90B compliant. We could test if
	 * fips_enabled should be set using the jent_fips_enabled() function,
	 * but this can be overridden using the JENT_FORCE_FIPS flag, which
	 * isn't passed in yet. It is better to run the tests on the small
	 * amount of data that we have, which should not fail unless things
	 * are really bad.
	 */
	ec = jent_entropy_collector_alloc_internal(0, JENT_FORCE_FIPS |
				(enable_notime ? JENT_FORCE_INTERNAL_TIMER :
						 JENT_DISABLE_INTERNAL_TIMER));
	if (!ec) {
		ret = EMEM;
		goto out;
	}

	if (jent_notime_settick(ec)) {
		ret = EMEM;
		goto out;
	}

	/* To initialize the prior time. */
	jent_measure_jitter(ec, 0, NULL);

	/* We could perform statistical tests here, but the problem is
	 * that we only have a few loop counts to do testing. These
	 * loop counts may show some slight skew leading to false positives.
	 */

	/*
	 * We could add a check for system capabilities such as clock_getres or
	 * check for CONFIG_X86_TSC, but it does not make much sense as the
	 * following sanity checks verify that we have a high-resolution
	 * timer.
	 */
#define CLEARCACHE 100
	for (i = -CLEARCACHE; i < JENT_POWERUP_TESTLOOPCOUNT; i++) {
		uint64_t start_time = 0, end_time = 0, delta = 0;
		unsigned int stuck;

		/* Invoke core entropy collection logic */
		stuck = jent_measure_jitter(ec, 0, &delta);
		end_time = ec->prev_time;
		start_time = ec->prev_time - delta;

		/* test whether timer works */
		if (!start_time || !end_time) {
			ret = ENOTIME;
			goto out;
		}

		/*
		 * test whether timer is fine grained enough to provide
		 * delta even when called shortly after each other -- this
		 * implies that we also have a high resolution timer
		 */
		if (!delta || (end_time == start_time)) {
			ret = ECOARSETIME;
			goto out;
		}

		/*
		 * up to here we did not modify any variable that will be
		 * evaluated later, but we already performed some work. Thus we
		 * already have had an impact on the caches, branch prediction,
		 * etc. with the goal to clear it to get the worst case
		 * measurements.
		 */
		if (i < 0)
			continue;

		if (stuck)
			count_stuck++;

		/* test whether we have an increasing timer */
		if (!(end_time > start_time))
			time_backwards++;

		/* Watch for common adjacent GCD values */
		jent_gcd_add_value(delta_history, delta, i);
	}

	/*
	 * we allow up to three times the time running backwards.
	 * CLOCK_REALTIME is affected by adjtime and NTP operations. Thus,
	 * if such an operation just happens to interfere with our test, it
	 * should not fail. The value of 3 should cover the NTP case being
	 * performed during our test run.
	 */
	if (time_backwards > 3) {
		ret = ENOMONOTONIC;
		goto out;
	}

	/* First, did we encounter a health test failure? */
	if ((health_test_result = jent_health_failure(ec))) {
		ret = (health_test_result & JENT_RCT_FAILURE) ? ERCT : EHEALTH;
		goto out;
	}

	ret = jent_gcd_analyze(delta_history, JENT_POWERUP_TESTLOOPCOUNT);
	if (ret)
		goto out;

	/*
	 * If we have more than 90% stuck results, then this Jitter RNG is
	 * likely to not work well.
	 */
	if (JENT_STUCK_INIT_THRES(JENT_POWERUP_TESTLOOPCOUNT) < count_stuck)
		ret = ESTUCK;

out:
	jent_gcd_fini(delta_history, JENT_POWERUP_TESTLOOPCOUNT);

	if (enable_notime && ec)
		jent_notime_unsettick(ec);

	jent_entropy_collector_free(ec);

	return ret;
}

JENT_PRIVATE_STATIC
int jent_entropy_init(void)
{
	int ret;

	jent_notime_block_switch();

	if (sha3_tester())
		return EHASH;

	ret = jent_time_entropy_init(0);

#ifdef JENT_CONF_ENABLE_INTERNAL_TIMER
	if (ret)
		ret = jent_time_entropy_init(1);
#endif /* JENT_CONF_ENABLE_INTERNAL_TIMER */

	return ret;
}

JENT_PRIVATE_STATIC
int jent_entropy_switch_notime_impl(struct jent_notime_thread *new_thread)
{
	return jent_notime_switch(new_thread);
}
