/* Copyright (c) (2011,2013-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccperf.h"
#include <math.h>


static int compare_doubles(const void *a, const void *b) {
    const double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x == y ? 0 : 1;
}

double histogram_sieve(struct ccperf_family *f, size_t *psize, const void *arg)
{
    const unsigned int nruns_min = 10;
    const unsigned int nruns_max = 500;
    unsigned int nruns=nruns_max;
    double *runs = calloc(nruns_max, sizeof(double));
    /* Run the function nruns times. */
    struct standard_deviation sd;
    double tt=0;

    for (unsigned int run = 0; run < nruns_max; ++run) {
        double t = f->func(f->loops, psize, arg);
        runs[run] = t;

        if (run) {
            standard_deviation_add(&sd, t);
        } else {
            standard_deviation_add_first(&sd, t);
        }

        /* Stop running tests if we go over 10 seconds total elapsed time. */
        tt += t;
        if ((tt > RUN_TIMEOUT) && (run > nruns_min)) {
            nruns = run + 1;
            break;
        }
    }
    f->nruns=nruns;
    f->run_time=tt;

    /* Sort the run times. */
    qsort(runs, nruns, sizeof(double), compare_doubles);
    /* Now find the longest series in nruns that has close to the same value. */
    /* Perhaps we'd like to define close in terms of sigma. */
    // double sigma = standard_deviation_sigma(&sd);
    /* We want the leading edge of the set of values closest together. */
    unsigned int edge = 0;
    unsigned int best = 0;
    unsigned int best_len = 0;
    double dmin = runs[nruns - 1] - runs[0];
    double median = runs[nruns / 2];
    /* Accuracy desired is 0.01% of the median time.  We could do something
     with sigma here too, but I'm not sure what. */
    //double threshold = median / (nruns * 10.0);
    double threshold = median / 100000; // ((pt->type == n_slow) ? 100 : 100000);
    //double threshold = sigma / (nruns * 10.0);

    for (unsigned int run = 1; run < nruns; ++run) {
        double delta = runs[run] - runs[run - 1];
        if (delta < dmin) {
            dmin = delta;
        }
        while ((runs[run] - runs[edge]) > threshold) {
            if (run - edge > best_len) {
#if 0
                /* Display best run each time a new one is selected. */
                struct units ur = dur2units(runs[edge]);
                struct units ue = dur2units(e);
                printf("%u[%u]: %6.3g %s delta: %6.3g %s\n", edge, run - edge,
                       runs[edge] * ur.scale, ur.name,
                       (runs[run] - runs[edge]) * ue.scale, ue.name);
#endif
                best_len = run - edge;
                best = edge;
            }
            edge++;
        }
    }
    /* If we are verbose or we have a run [best, best + best_len> with less
     than 15% of the total samples, or sigma (the standard deviation), is
     more than 25%  of  the lower edge  of  the selected  run, unless the
     selected run contains 75% or more of the samples. */
#if 0
    if (verbose || best_len < nruns * 0.15 ||
        (sigma > runs[best] * 0.25 && best_len < nruns * 0.75)) {
        struct units u = dur2units(runs[best]);
        struct units ut = dur2units(threshold);
        struct units um = dur2units(median);
        struct units umean = dur2units(sd.M);
        struct units udmin = dur2units(runs[rdmin]);
        struct units us = dur2units(sigma);
        if (best_len < nruns * 0.15 || sigma > runs[best] * 0.25) {
            struct units ud = dur2units(dmin);
            printf("*** %5.3g%% matched %u@%u/%u: %5.3g %s(%4.3g%%) "
                   "dmin: %5.3g %s %5.3g %s@%u thres: %5.3g %s\n",
                   (100.0 * best_len) / nruns, best_len, best, nruns,
                   runs[best] * u.scale, u.name,
                   (sigma * 100.0) / runs[best],
                   dmin * ud.scale, ud.name,
                   runs[rdmin] * udmin.scale, udmin.name, rdmin,
                   threshold * ut.scale, ut.name);
        } else if (verbose) {
            printf("%5.3g%% matched %u@%u/%u: %5.3g %s(%4.3g%%) "
                   "thres: %5.3g %s\n",
                   (100.0 * best_len) / nruns, best_len, best, nruns,
                   runs[best] * u.scale, u.name,
                   (sigma * 100.0) / runs[best],
                   threshold * ut.scale, ut.name);
        }
        printf(" sigma: %6.3g %s median: %6.3g %s(%4.3g%%) "
               "mean: %6.3g %s(%4.3g%%)\n",
               sigma * us.scale, us.name,
               median * um.scale, um.name,
               (sigma * 100.0) / median,
               sd.M * umean.scale, umean.name,
               (sigma * 100.0) / sd.M);
    }
#endif

    // Consider averaging runs[best] - runs[best + best_len]
    double result = runs[best];
    free(runs);

    return result;
#if 0
    /* Sum of differences with the median (sd) and sum of squares of differences
     with the median (sdd). */
    double median = runs[nruns / 2];
    double sd = 0.0, sdd = 0.0;
    for (unsigned int run = 0; run < nruns; ++run) {
        double d = run < nruns / 2 ? median - runs[run] : run == nruns / 2 ? 0.0 : runs[run] - median;
        sd += d;
        sdd += d * d;
    }
#endif
}

#if 0
/* Technically this is an incremental/decremental linear regression. */
struct line_fit {
    double sx;
    double sxx;
    double sy;
    double sxy;
    unsigned int np;
};

CC_UNUSED CC_INLINE void line_fit_init(struct line_fit *cf) {
    cf->sx = 0.0;
    cf->sxx = 0.0;
    cf->sy = 0.0;
    cf->sxy = 0.0;
    cf->np = 0;
}

CC_UNUSED CC_INLINE void line_fit_add_point(struct line_fit *cf, double x, double y) {
    cf->sx += x;
    cf->sxx += x * x;
    cf->sy += y;
    cf->sxy += x * y;
    cf->np++;
    //printf("ap:(%g, %g)\n", x, y);
}

CC_UNUSED CC_INLINE void line_fit_remove_point(struct line_fit *cf, double x, double y) {
    cf->sx -= x;
    cf->sxx -= x * x;
    cf->sy -= y;
    cf->sxy -= x * y;
    cf->np--;
}

struct line_fit_params {
    double slope;
    double offset;
};

CC_UNUSED CC_INLINE struct line_fit_params line_fit_params(const struct line_fit *cf) {
    struct line_fit_params params;
    double a = cf->np * cf->sxx - cf->sx * cf->sx;
    /* Prevent division by zero */
    if (fabs(a) > 1.0e-12) {
        double c = 1.0 / a;
        params.slope = c * (cf->np * cf->sxy - cf->sx * cf->sy);
        params.offset = c * (cf->sxx * cf->sy - cf->sx * cf->sxy);
        /* The alternative:
         params.offset = (cf->sy - cf->slope * cf->sx) / cf->np;
         is slower if divide takes more than twice as long as multiply since it uses 1 multiply and 1 divide instead of 3 multiplies. */
    } else {
        params.slope = 0.0;
        params.offset = 0.0;
    }
    return params;
}

/* Return values for a and b such that f(x) = a * x + b */
static double sof_squares(unsigned int m, unsigned int x[], double y[], double a, double b, int *psign) {
    double sum = 0.0;
    int sign = 0;
    for (unsigned int i = 0; i < m; ++i) {
        double fx = a * x[i] + b;
        double diff = y[i] - fx;
        if (diff > 0)
            sign++;
        else if (diff < 0)
            sign--;
        double square = diff * diff;
        sum += square;
    }
    *psign = sign;
    return sum;
}

static void levenberg_marquardt(unsigned int m, unsigned int x[], double y[], double *pa, double *pb) {
    /* Start off with a function though (x[0],y[0]) and (x[m-1],y[m-1]) */
    double a = (y[m-1]-y[0]) / (x[m-1]-x[0]), b = y[0]-a*x[0];

    int sign;
    double da = 0, db = 0;
    double sos = sof_squares(m, x, y, a, b, &sign);
    do {
        if (sign < -1)
            db += sqrt(sos) / 7;
        else if (sign > 1)
            db -= sqrt(sos) / 7;
        else if (sign < 0)
            da += sqrt(sos) / a * 37;
        else if (sign >= 0)
            da -= sqrt(sos) / a * 37;
        double s = sof_squares(m, x, y, a + da, b + db, &sign);
        if (s < sos) {
            a += da;
            b += db;
            sos = s;
            da = 0.0;
            db = 0.0;
        } else {
            s = sof_squares(m, x, y, a - da, b + db, &sign);
            if (s < sos) {
                a -= da;
                b += db;
                sos = s;
                da = 0.0;
                db = 0.0;
            }
        }
    } while (sos > (10^(-20)));

    //printf("sum of squares: %g\n", sos);

    *pa = a;
    *pb = b;
}
#endif
