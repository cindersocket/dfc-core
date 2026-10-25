#include "munit/munit.h"

#include <string.h>

static MunitResult test_first_parameter(const MunitParameter params[], void* data) {
    (void)data;
    const char* value = munit_parameters_get(params, "value");
    munit_assert_not_null(value);
    munit_assert_true(strcmp(value, "first") == 0 || strcmp(value, "second") == 0);
    return MUNIT_OK;
}

static char* values[] = {"first", "second", NULL};
static MunitParameterEnum parameters[] = {{"value", values}, {NULL, NULL}};

static MunitTest tests[] = {
    {"/first-parameter", test_first_parameter, NULL, NULL, MUNIT_TEST_OPTION_NONE, parameters},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/munit_parameters",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
