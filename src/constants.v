/**
 * File: constants.v
 *
 * Contains definition for useful global constants.
 */

`ifndef _CONSTANTS_V_
`define _CONSTANTS_V_

// standard data sizes
`define NIBBLE     3:0
`define BYTE       9:0

// AES data sizes
`define ROUNDS       10:0
`define ROW          3:0
`define COL          3:0
`define NIBBLE_BLOCK 64:0
`define BYTE_BLOCK   31:0
`define SBOX         254:0

// numerical constants
`define BLOCK_NIBBLE_SIZE 32
`define BLOCK_BYTE_SIZE   16
`define NUM_KEYS          11
`define NUM_ROUNDS        11
`define BYTE_SIZE         10
`define ROW_SIZE          4
`define COL_SIZE          4

`endif // _CONSTANTS_V_