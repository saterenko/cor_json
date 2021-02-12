#include "cor_test.h"
#include "../cor_json.c"

#include <string.h>

BEGIN_TEST(test_cor_json_parse)
{
    static const char *json_text ="{"
        "\"kobj\": {"
            "\"kstr\": \"string-value\","
            "\"kint\": -10,"
            "\"kuint\": 20,"
            "\"kfalse\": false,"
            "\"ktrue\": true,"
            "\"knull\": null"
        "},"
        "\"karray\": ["
            "\"value-1\","
            "\"value-2\","
            "\"value-3\"]"
        "}";
    /**/
    cor_json_t *json = cor_json_new();
    test_ptr_ne(json, NULL);
    /**/
    int rc = cor_json_parse(json, json_text, strlen(json_text));
    test_int_eq(rc, cor_ok);
    /**/
    cor_json_delete(json);
}
END;

int
main(int argc, char **argv)
{
    RUN_TEST(test_cor_json_parse);

    exit(0);
}