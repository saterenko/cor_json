#include "cor_json.h"

#include <stdio.h>

static inline cor_json_node_t *cor_json_node_add_last(cor_json_t *json, cor_json_node_t *parent);
static inline enum cor_json_node_type_e cor_json_node_type(const char *p, size_t size);

cor_json_t *
cor_json_new()
{
    cor_pool_t *pool = cor_pool_new(COR_JSON_POOL_SIZE);
    if (!pool) {
        return NULL;
    }
    cor_json_t *json = cor_pool_calloc(pool, sizeof(cor_json_t));
    if (!json) {
        cor_pool_delete(pool);
        return NULL;
    }
    /**/
    json->pool = pool;

    return json;
}

void
cor_json_delete(cor_json_t *json)
{
    if (json && json->pool) {
        cor_pool_delete(json->pool);
    }
}

const char *
cor_json_error(cor_json_t *json)
{
    return json->error;
}

int
cor_json_parse(cor_json_t *json, const char *data, size_t size)
{
    static cor_json_node_t *stack[COR_JSON_STACK_SIZE];

#define cor_json_parse_error(_s) snprintf(json->error, COR_JSON_ERROR_SIZE, _s " in %u position", (unsigned int) (p - data))

    enum {
        begin_s,
        sp_before_key_s,
        quote_before_key_s,
        key_s,
        sp_before_colon_s,
        sp_after_colon_s,
        string_value_s,
        sp_before_array_value_s,
        other_value_s,
        sp_after_value_s,
        backslash_in_value_s,
        after_object_close_s
    } state;
    state = begin_s;
    const char *p = data;
    const char *end = p + size;
    /**/
    int stack_index = 0;
    stack[0] = &json->root;
    stack[0]->type = COR_JSON_NODE_OBJECT;
    cor_json_node_t *node = stack[0];
    /**/
    for (; p < end; p++) {
        char c = *p;
        switch (state) {
            case begin_s: {
                if (cor_unlikely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    break;
                }
                if (cor_likely(c == '{')) {
                    state = sp_before_key_s;
                    break;
                }
                cor_json_parse_error("bad symbol");
                return cor_error;
            }
            case sp_before_key_s: {
                if (cor_unlikely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    break;
                }
                if (cor_unlikely(c == '}')) {
                    if (cor_unlikely(--stack_index == -1)) {
                        p = end;
                        break;
                    }
                    state = after_object_close_s;
                    break;
                }
                if (cor_likely(c == '"')) {
                    state = quote_before_key_s;
                    break;
                }
                break;
            }
            case quote_before_key_s: {
                node = cor_json_node_add_last(json, stack[stack_index]);
                if (cor_unlikely(!node)) {
                    cor_json_parse_error("internal error");
                    return cor_error;
                }
                node->name = p;
                state = key_s;
                break;
            }
            case key_s: {
                if (cor_likely(c != '"')) {
                    break;
                }
                node->name_size = p - node->name;
                state = sp_before_colon_s;
                break;
            }
            case sp_before_colon_s: {
                if (cor_likely(c == ':')) {
                    state = sp_after_colon_s;
                    break;
                }
                if (cor_likely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    break;
                }
                cor_json_parse_error("bad symbol");
                return cor_error;
            }
            case sp_after_colon_s: {
                if (cor_unlikely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    break;
                }
                switch (c) {
                    case '"':
                        node->type = COR_JSON_NODE_STRING;
                        node->value = p + 1;
                        state = string_value_s;
                        break;
                    case '{':
                        if (++stack_index == COR_JSON_STACK_SIZE) {
                            cor_json_parse_error("maximum stack size exceed");
                            return cor_error;
                        }
                        node->type = COR_JSON_NODE_OBJECT;
                        stack[stack_index] = node;
                        state = sp_before_key_s;
                        break;
                    case '[':
                        if (++stack_index == COR_JSON_STACK_SIZE) {
                            cor_json_parse_error("maximum stack size exceed");
                            return cor_error;
                        }
                        node->type = COR_JSON_NODE_ARRAY;
                        stack[stack_index] = node;
                        state = sp_before_array_value_s;
                        break;
                    default:
                        node->value = p;
                        state = other_value_s;
                        break;
                }
                break;
            }
            case string_value_s: {
                if (cor_unlikely(c == '"')) {
                    node->value_size = p - node->value;
                    state = sp_after_value_s;
                    break;
                }
                if (cor_unlikely(c == '\\')) {
                    state = backslash_in_value_s;
                    break;
                }
                break;
            }
            case sp_before_array_value_s: {
                if (cor_unlikely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    break;
                }
                if (cor_unlikely(c == ']')) {
                    if (cor_unlikely(--stack_index == -1)) {
                        p = end;
                        break;
                    }
                    state = after_object_close_s;
                    break;
                }
                if (cor_likely(c == '"')) {
                    state = quote_before_key_s;
                    break;
                }
                break;
            }
            case other_value_s: {
                if (cor_unlikely(c == ',')) {
                    node->value_size = p - node->value;
                    node->type = cor_json_node_type(node->value, node->value_size);
                    if (node->type == COR_JSON_NODE_UNDEFINED) {
                        cor_json_parse_error("undefined value type");
                        return cor_error;
                    }
                    state = sp_before_key_s;
                    break;
                }
                if (cor_unlikely(c == '}')) {
                    node->value_size = p - node->value;
                    node->type = cor_json_node_type(node->value, node->value_size);
                    if (node->type == COR_JSON_NODE_UNDEFINED) {
                        cor_json_parse_error("undefined value type");
                        return cor_error;
                    }
                    if (--stack_index == -1) {
                        p = end;
                        break;
                    }
                    state = after_object_close_s;
                    break;
                }
                break;
            }
            case sp_after_value_s: {
                if (cor_likely(c == ',')) {
                    state = sp_before_key_s;
                    break;
                }
                if (cor_likely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    break;
                }
                if (cor_likely(c == '}')) {
                    if (--stack_index == -1) {
                        p = end;
                        break;
                    }
                    state = after_object_close_s;
                    break;
                }
                cor_json_parse_error("bad symbol");
                return cor_error;
            }
            case backslash_in_value_s: {
                if (cor_unlikely(c == '\\')) {
                    break;
                }
                state = string_value_s;
                break;
            }
            case after_object_close_s:
                if (cor_unlikely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    break;
                }
                if (cor_unlikely(c == '}')) {
                    if (--stack_index == -1) {
                        p = end;
                    }
                    break;
                }
                if (cor_likely(c == ',')) {
                    state = sp_before_key_s;
                    break;
                }
                break;
        }
    }

#undef cor_json_parse_error

    return cor_ok;
}

static inline cor_json_node_t *
cor_json_node_add_last(cor_json_t *json, cor_json_node_t *parent)
{
    cor_json_node_t *n = cor_pool_calloc(json->pool, sizeof(cor_json_node_t));
    if (!n) {
        return NULL;
    }
    /*  add node to the list  */
    if (parent->last_child) {
        parent->last_child->next_sibling = n;
    } else {
        parent->first_child = n;
    }
    parent->last_child = n;

    return n;
}

static inline enum cor_json_node_type_e
cor_json_node_type(const char *p, size_t size)
{
    enum {
        begin_s,
        exp_digit_s,
        number_s,
        number_after_point_s,
        number_after_point_number_s,
        number_after_exp_s,
        exp_fa_s,
        exp_fal_s,
        exp_fals_s,
        exp_false_s,
        exp_tr_s,
        exp_tru_s,
        exp_true_s,
        exp_nu_s,
        exp_nul_s,
        exp_null_s,
        exp_spaces_s
    } state;
    state = begin_s;
    enum cor_json_node_type_e type = COR_JSON_NODE_UNDEFINED;
    const char *end = p + size;
    for (; p < end; p++) {
        char c = *p;
        switch (state) {
            case begin_s:
                if (cor_unlikely(c == '-')) {
                    type = COR_JSON_NODE_INT;
                    state = exp_digit_s;
                    break;
                }
                if (cor_likely(c >= '0' && c <= '9')) {
                    type = COR_JSON_NODE_UINT;
                    state = number_s;
                    break;
                }
                char ch = c | 0x20; /*  lowercase  */
                switch (ch) {
                    case 'f':
                        state = exp_fa_s;
                        break;
                    case 'n':
                        state = exp_nu_s;
                        break;
                    case 't':
                        state = exp_tr_s;
                        break;
                    default:
                        return COR_JSON_NODE_UNDEFINED;
                }
                break;
            case exp_digit_s:
                if (cor_likely(c >= '0' && c <= '9')) {
                    state = number_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case number_s:
                if (cor_likely(c >= '0' && c <= '9')) {
                    break;
                }
                if (cor_likely(c == '.')) {
                    type = COR_JSON_NODE_FLOAT;
                    state = number_after_point_s;
                    break;
                }
                if (cor_likely(c == 'e')) {
                    state = number_after_exp_s;
                    break;
                }
                if (cor_likely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    state = exp_spaces_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case number_after_point_s:
                if (cor_likely(c >= '0' && c <= '9')) {
                    state = number_after_point_number_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case number_after_point_number_s:
                if (cor_likely(c >= '0' && c <= '9')) {
                    break;
                }
                if (cor_likely(c == 'e')) {
                    state = number_after_exp_s;
                    break;
                }
                if (cor_likely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    state = exp_spaces_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case number_after_exp_s:
                if (cor_likely(c >= '0' && c <= '9')) {
                    break;
                }
                if (cor_likely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    state = exp_spaces_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_fa_s:
                if (cor_likely((c | 0x20) == 'a')) {
                    state = exp_fal_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_fal_s:
                if (cor_likely((c | 0x20) == 'l')) {
                    state = exp_fals_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_fals_s:
                if (cor_likely((c | 0x20) == 's')) {
                    state = exp_false_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_false_s:
                if (cor_likely((c | 0x20) == 'e')) {
                    type = COR_JSON_NODE_BOOL;
                    state = exp_spaces_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_tr_s:
                if (cor_likely((c | 0x20) == 'r')) {
                    state = exp_tru_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_tru_s:
                if (cor_likely((c | 0x20) == 'u')) {
                    state = exp_true_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_true_s:
                if (cor_likely((c | 0x20) == 'e')) {
                    type = COR_JSON_NODE_BOOL;
                    state = exp_spaces_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_nu_s:
                if (cor_likely((c | 0x20) == 'u')) {
                    state = exp_nul_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_nul_s:
                if (cor_likely((c | 0x20) == 'l')) {
                    state = exp_null_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_null_s:
                if (cor_likely((c | 0x20) == 'l')) {
                    type = COR_JSON_NODE_NULL;
                    state = exp_spaces_s;
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
            case exp_spaces_s:
                if (cor_likely(c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
                    break;
                }
                return COR_JSON_NODE_UNDEFINED;
        }
    }

    return type;
}
