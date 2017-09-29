#include "garble.h"
#include "garble/garble_gate_halfgates.h"
#include "garble/garble_gate_privacy_free.h"
#include "garble/garble_gate_standard.h"

#include <assert.h>
#include <string.h>

static void
_eval_privacy_free(const garble_circuit *gc, block *labels, const AES_KEY *key)
{
    size_t nxors = 0;
    for (size_t i = 0; i < gc->q; i++) {
        garble_gate *g = &gc->gates[i];
        nxors += (g->type == GARBLE_GATE_XOR ? 1 : 0);
        garble_gate_eval_privacy_free(g->type,
                                      labels[g->input0],
                                      labels[g->input1],
                                      &labels[g->output],
                                      &gc->table[i - nxors],
                                      i, key);
    }
}

static void
_eval_halfgates(const garble_circuit *gc, block *labels, const AES_KEY *key)
{
    size_t nxors = 0;
    for (size_t i = 0; i < gc->q; i++) {
        garble_gate *g = &gc->gates[i];
        nxors += (g->type == GARBLE_GATE_XOR ? 1 : 0);

        // uint16_t *val = (uint16_t*) &(labels[g->input0]);
        // char buffer[100];

        // sprintf(buffer,"%i%i%i%i%i%i%i%i",val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]);
        // printf("%s\n", buffer);

        // val = (uint16_t*) &(labels[g->input1]);
        // sprintf(buffer,"%i%i%i%i%i%i%i%i",val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]);
        // printf("%s\n", buffer);


        garble_gate_eval_halfgates(g->type,
                                   labels[g->input0],
                                   labels[g->input1],
                                   &labels[g->output],
                                   &gc->table[2 * (i - nxors)],
                                   i, key);


        // val = (uint16_t*) &(labels[g->output]);
        // sprintf(buffer,"%i%i%i%i%i%i%i%i",val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]);
        // printf("%s\n", buffer);

    }


    // printf("HG evaluated\n");

}

static void
_eval_standard(const garble_circuit *gc, block *labels, AES_KEY *key)
{
    size_t nxors = 0;
    for (size_t i = 0; i < gc->q; i++) {
        garble_gate *g = &gc->gates[i];
        nxors += (g->type == GARBLE_GATE_XOR ? 1 : 0);
        garble_gate_eval_standard(g->type,
                                  labels[g->input0],
                                  labels[g->input1],
                                  &labels[g->output],
                                  &gc->table[3 * (i - nxors)],
                                  i, key);
    }
}

int
garble_eval(const garble_circuit *gc, const block *input_labels,
            block *output_labels, bool *outputs)
{
    AES_KEY key;
    block *labels;
    block fixed_label;

    if (gc == NULL)
        return GARBLE_ERR;

    AES_set_encrypt_key(gc->global_key, &key);
    labels = garble_allocate_blocks(gc->r);

    /* Set input wire labels */
    memcpy(labels, input_labels, gc->n * sizeof input_labels[0]);

    /* Set fixed wire labels */
    fixed_label = gc->fixed_label;
    *((char *) &fixed_label) &= 0xfe;
    labels[gc->n] = fixed_label;
    *((char *) &fixed_label) |= 0x01;
    labels[gc->n + 1] = fixed_label;

    switch (gc->type) {
    case GARBLE_TYPE_STANDARD:
        _eval_standard(gc, labels, &key);
        break;
    case GARBLE_TYPE_HALFGATES:
        _eval_halfgates(gc, labels, &key);
        break;
    case GARBLE_TYPE_PRIVACY_FREE:
        _eval_privacy_free(gc, labels, &key);
        break;
    }

    // printf("Going to test output\n");

    if (output_labels) {
        for (size_t i = 0; i < gc->m; ++i) {
            output_labels[i] = labels[gc->outputs[i]];
    //         uint16_t *val = (uint16_t*) &(output_labels[i]);
    //         char buffer[100];
    //
    //         sprintf(buffer,"%i%i%i%i%i%i%i%i",val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]);
    //         printf("%s\n", buffer);
    //
        }
    }
    // printf("Labels done\n");
    for (int i = 0; i < gc->m; ++i)
    {
        gc->outputs[i]=i;
    //     printf("%d ", gc->outputs[i]);
    //     printf("%d\n", gc->output_perms[i] );
    }
    // printf("\n");
    if (outputs) {
         for (size_t i = 0; i < gc->m; ++i) {
             outputs[i] =
                 (*((char *) &labels[gc->outputs[i]]) & 0x1) ^ gc->output_perms[i];
            //  printf("%d\n ",outputs[i] );
         }
     }

    //  printf("outputs done\n");

    free(labels);

    // printf("going to fair\n");

    return GARBLE_OK;
}

void
garble_extract_labels1(block *extracted_labels, const block *labels,
                      const bool *bits, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        extracted_labels[i] = labels[2 * i + (bits[i] ? 1 : 0)];
        // uint16_t *val = (uint16_t*) &(extracted_labels[i]);
        // char buffer[100];
        //
        // sprintf(buffer,"%i%i%i%i%i%i%i%i",val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]);
        // printf("%s\n", buffer);
    }
}


void
garble_extract_labels2(block *extracted_labels, const block *labels,
                      const bool *bits, size_t nst, size_t ned)
{
    for (size_t i = nst; i < ned; ++i) {
        extracted_labels[i] = labels[2 * i + (bits[i] ? 1 : 0)];
        // uint16_t *val = (uint16_t*) &(extracted_labels[i]);
        // char buffer[100];

        // sprintf(buffer,"%i%i%i%i%i%i%i%i",val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]);
        // printf("%s\n", buffer);

    }
}

int
garble_map_outputs(const block *output_labels, const block *map, bool *vals,
                   size_t m)
{
    for (size_t i = 0; i < m; i++) {
        if (garble_equal(map[i], output_labels[2 * i])) {
            vals[i] = false;
        } else if (garble_equal(map[i], output_labels[2 * i + 1])) {
            vals[i] = true;
        } else {
            return GARBLE_ERR;
        }
    }
    return GARBLE_OK;
}
