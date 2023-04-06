/**
 * File: aes_ced_tb.v
 *
 * Contains the testbench for testing full AES encryption
 * with concurrent error detection (CED).
 *
 * input: in.txt
 * output: out.txt
 *
 * input file format:
 * <faulty bit> <round number> <operation> <row offset1> <byte offset1> <bit offset1> <row offset2> <byte offset2> <bit offset2>
 * <plain text>
 * <cipher text>
 */

`include "constants.v"
`include "hex.v"
`include "sbox.v"

module aes_ced_tb();

    integer iterator = 0;

    integer fault_flag = 0;
    integer fault_round = 0;
    integer fault_operation = 0;
    integer fault_row[1:0];
    integer fault_col[1:0];
    integer fault_bit[1:0];

    reg fault_detected = 1'h0;

    reg parity_predict[`NIBBLE];
    reg parity[`NIBBLE];

    reg[`BYTE] buffer;
    integer in_file;
    integer out_file;

    reg[`BYTE] plaintext_str[`NIBBLE_BLOCK];
    reg[`BYTE] key_str[`NIBBLE_BLOCK];

    reg[`BYTE] plaintext[`ROW][`COL];
    reg[`BYTE] key_0[`ROW][`COL];

    // used for column mixing
    reg[`BYTE] z[`ROW];

    // used for key generation
    reg[`BYTE] key[`ROUNDS][`ROW][`COL];
    reg[`BYTE] g[`COL];
    reg[`BYTE] rc[`ROUNDS];

    // used for sbox parity check
    reg[`BYTE] round_input[`ROW][`COL];

    initial begin
        
        // open in and out text files
        in_file = $fopen("in.txt", "r");
        out_file = $fopen("out.txt", "w");

        // get fault injector parameters
        buffer = $fscanf(in_file, "%d %d %d %d %d %d %d %d %d\n", fault_flag, fault_round, fault_operation,
            fault_row[0], fault_col[0], fault_bit[0], fault_row[1], fault_col[1], fault_bit[1]);

        // get the key
        for (integer i = 0; `BLOCK_NIBBLE_SIZE > i; i++) begin
            buffer[`BYTE] = $fgetc(in_file);
            key_str[i] = buffer[`BYTE];
        end

        // get the plaintext
        buffer[`BYTE] = $fgetc(in_file);
        for (integer i = 0; `BLOCK_NIBBLE_SIZE > i; i++) begin
            buffer[`BYTE] = $fgetc(in_file);
            plaintext_str[i] = buffer[`BYTE];
        end

        // place key into 4x4 byte table
        iterator = 0;
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                buffer[7:4] = ascii_to_hex(key_str[iterator++]);
                buffer[3:0] = ascii_to_hex(key_str[iterator++]);
                key_0[j][i] = buffer;
            end
        end

        // place plaintext into 4x4 byte table
        iterator = 0;
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                buffer[7:4] = ascii_to_hex(plaintext_str[iterator++]);
                buffer[3:0] = ascii_to_hex(plaintext_str[iterator++]);
                plaintext[j][i] = buffer;
            end
        end

        $write("key: ");
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                    $write("%x", key_0[j][i][7:0]);
            end
        end
        $write("\n");

        $write("plaintext: ");
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                    $write("%x", plaintext[j][i][7:0]);
            end
        end
        $write("\n\n");

//****************************************************************************************** AES BEGIN


//////////////////////////////////////////////////////////////////////////////////////////// KEY GENERATION

        // set RC values
        rc[0] = 10'b0000000000;
        rc[1] = 10'b0000000001;
        rc[2] = 10'b0000000010;
        rc[3] = 10'b0000000100;
        rc[4] = 10'b0000001000;
        rc[5] = 10'b0000010000;
        rc[6] = 10'b0000100000;
        rc[7] = 10'b0001000000;
        rc[8] = 10'b0010000000;
        rc[9] = 10'b0000011011;
        rc[10] = 10'b0000110110;

        // place the zeroeth key into w
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                key[0][j][i] = key_0[j][i];
            end
        end

        for (integer rnd = 1; `NUM_ROUNDS > rnd; rnd++) begin

            // calculate g
            g[0] = byte_xor_byte(sbox(key[rnd-1][1][3]), rc[rnd]);
            g[1] = sbox(key[rnd-1][2][3]);
            g[2] = sbox(key[rnd-1][3][3]);
            g[3] = sbox(key[rnd-1][0][3]);

            // calculate w4
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                key[rnd][i][0] = byte_xor_byte(g[i], key[rnd-1][i][0]);
            end

            // calculate w5
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                key[rnd][i][1] = byte_xor_byte(key[rnd][i][0], key[rnd-1][i][1]);
            end

            // calculate w6
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                key[rnd][i][2] = byte_xor_byte(key[rnd][i][1], key[rnd-1][i][2]);
            end

            // calculate w7
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                key[rnd][i][3] = byte_xor_byte(key[rnd][i][2], key[rnd-1][i][3]);
            end
            
        end

//////////////////////////////////////////////////////////////////////////////////////////// ROUND 0

        $display("Round 0");

        // perform AES key XOR
        for (integer i = 0; `ROW_SIZE > i; i++) begin
            for (integer j = 0; `COL_SIZE > j; j++) begin
                plaintext[i][j] = byte_xor_byte(plaintext[i][j], key[0][i][j]);
            end
        end

        $write("round key: ");
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                $write("%x", key[0][j][i][7:0]);
            end
        end
        $write("\n");

        $write("key xor: ");
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                    $write("%x", plaintext[j][i][7:0]);
            end
        end
        $write("\n\n");

//////////////////////////////////////////////////////////////////////////////////////////// ROUNDS 1 - 9

        for (integer rnd = 1; `NUM_ROUNDS - 1 > rnd; rnd++) begin

            $display("Round %0d", rnd);

            // create a copy of plaintext for round input
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    round_input[i][j] = plaintext[i][j];
                end
            end

            // perform sbox conversion
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    plaintext[i][j] = sbox_with_parity(plaintext[i][j]);
                end
            end

            // inject fault(s) into output of sbox conversion
            if (1 == fault_flag && fault_round == rnd && `FAULT_SBOX == fault_operation) begin

                plaintext[fault_row[0]][fault_col[0]] ^= (rc[8] >> fault_bit[0]);
                $display("*** Fault injected in SBox at [%0d][%0d][%0d]", fault_row[0], fault_col[0], fault_bit[0]);
 
                // second fault
                if (fault_row[0] != fault_row[1] 
                    || fault_col[0] != fault_col[1]
                    || fault_bit[0] != fault_bit[1]) begin

                    plaintext[fault_row[1]][fault_col[1]] ^= (rc[8] >> fault_bit[1]);
                    $display("*** Fault injected in Sbox at [%0d][%0d][%0d]", fault_row[1], fault_col[1], fault_bit[1]);
                end
            end

            // determine if fault present in sbox conversion
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    if (plaintext[i][j][`PARITY_BIT_SBOX] 
                        != (^round_input[i][j][`DATA_BITS_SBOX]) ^ (^plaintext[i][j][`DATA_BITS_SBOX])) begin
                        
                        fault_detected = 1'h1;
                        $display("!!! Fault detected in SBox at [%0d][%0d]", i, j);
                    end
                end
            end

            // remove parity bit from sbox
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    plaintext[i][j][`PARITY_BIT_SBOX] = 1'h0;
                end
            end

            // print out the result of the sbox conversion
            $write("sbox: ");
            for (integer i = 0; `COL_SIZE > i; i++) begin
                for (integer j = 0; `ROW_SIZE > j; j++) begin
                    $write("%x", plaintext[j][i][7:0]);
                end
            end
            $write("\n");

            // predict parity of row shift
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                parity_predict[i] = 1'h0;
            end
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    parity_predict[i] ^= ^plaintext[i][j];
                end
            end

            // perform an AES row shift
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; j < i; j++) begin
                    buffer = plaintext[i][0];
                    plaintext[i][0] = plaintext[i][1];
                    plaintext[i][1] = plaintext[i][2];
                    plaintext[i][2] = plaintext[i][3];
                    plaintext[i][3] = buffer;
                end
            end

            // inject fault(s) into output of row shift
            if (1 == fault_flag && fault_round == rnd && `FAULT_ROW_SHIFT == fault_operation) begin

                plaintext[fault_row[0]][fault_col[0]] ^= (rc[8] >> fault_bit[0]);
                $display("*** Fault injected in Row Shift at [%0d][%0d][%0d]", fault_row[0], fault_col[0], fault_bit[0]);
 
                // second fault
                if (fault_row[0] != fault_row[1] 
                    || fault_col[0] != fault_col[1]
                    || fault_bit[0] != fault_bit[1]) begin

                    plaintext[fault_row[1]][fault_col[1]] ^= (rc[8] >> fault_bit[1]);
                    $display("*** Fault injected in Row Shift at [%0d][%0d][%0d]", fault_row[1], fault_col[1], fault_bit[1]);
                end
            end

            // get parity of row shift
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                parity[i] = 1'h0;
            end
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    parity[i] ^= ^plaintext[i][j];
                end
            end

            // determine if fault present for row shift
            for (integer i = 0; `COL_SIZE > i; i++) begin
                if (parity_predict[i] != parity[i]) begin
                    fault_detected = 1'h1;
                    $display("!!! Fault detected in Row Shift in row %0d", i);
                end
            end

            // print out the result of the row shift
            $write("rowshift: ");
            for (integer i = 0; `COL_SIZE > i; i++) begin
                for (integer j = 0; `ROW_SIZE > j; j++) begin
                    $write("%x", plaintext[j][i][7:0]);
                end
            end
            $write("\n");

            // predict parity of column mix
            for (integer i = 0; `COL_SIZE > i; i++) begin
                parity_predict[i] = 1'h0;
            end
            for (integer j = 0; `COL_SIZE > j; j++) begin
                for (integer i = 0; `ROW_SIZE > i; i++) begin
                    parity_predict[j] ^= ^plaintext[i][j];
                end
            end

            // perform AES column mix
            for (integer i = 0; `COL_SIZE > i; i++) begin

                // save column into z
                for (integer j = 0; `ROW_SIZE > j; j++) begin
                    z[j] = plaintext[j][i];
                end

                // calculate u0
                plaintext[0][i] = byte_mult_byte(z[0], 2); 
                plaintext[0][i] = byte_xor_byte(plaintext[0][i], byte_mult_byte(z[1], 3)); 
                plaintext[0][i] = byte_xor_byte(plaintext[0][i], z[2]); 
                plaintext[0][i] = byte_xor_byte(plaintext[0][i], z[3]);
                plaintext[0][i] = ip_op(plaintext[0][i]);
                

                // calculate u1
                plaintext[1][i] = z[0];
                plaintext[1][i] = byte_xor_byte(plaintext[1][i], byte_mult_byte(z[1], 2));
                plaintext[1][i] = byte_xor_byte(plaintext[1][i], byte_mult_byte(z[2], 3));
                plaintext[1][i] = byte_xor_byte(plaintext[1][i], z[3]);
                plaintext[1][i] = ip_op(plaintext[1][i]);

                // calculate u2
                plaintext[2][i] = z[0]; 
                plaintext[2][i] = byte_xor_byte(plaintext[2][i], z[1]);
                plaintext[2][i] = byte_xor_byte(plaintext[2][i], byte_mult_byte(z[2], 2));
                plaintext[2][i] = byte_xor_byte(plaintext[2][i], byte_mult_byte(z[3], 3));
                plaintext[2][i] = ip_op(plaintext[2][i]);

                // calculate u3
                plaintext[3][i] = byte_mult_byte(z[0], 3);
                plaintext[3][i] = byte_xor_byte(plaintext[3][i], z[1]); 
                plaintext[3][i] = byte_xor_byte(plaintext[3][i], z[2]);
                plaintext[3][i] = byte_xor_byte(plaintext[3][i], byte_mult_byte(z[3], 2));
                plaintext[3][i] = ip_op(plaintext[3][i]);

            end

            // inject fault(s) into output of column mix
            if (1 == fault_flag && fault_round == rnd && `FAULT_COL_MIX == fault_operation) begin

                plaintext[fault_row[0]][fault_col[0]] ^= (rc[8] >> fault_bit[0]);
                $display("*** Fault injected in Column Mix at [%0d][%0d][%0d]", fault_row[0], fault_col[0], fault_bit[0]);
 
                // second fault
                if (fault_row[0] != fault_row[1] 
                    || fault_col[0] != fault_col[1]
                    || fault_bit[0] != fault_bit[1]) begin

                    plaintext[fault_row[1]][fault_col[1]] ^= (rc[8] >> fault_bit[1]);
                    $display("*** Fault injected in Column Mix at [%0d][%0d][%0d]", fault_row[1], fault_col[1], fault_bit[1]);
                end
            end

            // get parity of column mix
            for (integer i = 0; `COL_SIZE > i; i++) begin
                parity[i] = 1'h0;
            end
            for (integer j = 0; `COL_SIZE > j; j++) begin
                for (integer i = 0; `ROW_SIZE > i; i++) begin
                    parity[j] ^= ^plaintext[i][j];
                end
            end

            // determine if fault present for column mix
            for (integer i = 0; `COL_SIZE > i; i++) begin
                if (parity_predict[i] != parity[i]) begin
                    fault_detected = 1'h1;
                    $display("!!! Fault detected in Column Mix in column %0d", i);
                end
            end

            // print out the result of the column mix
            $write("column mix: ");
            for (integer i = 0; `COL_SIZE > i; i++) begin
                for (integer j = 0; `ROW_SIZE > j; j++) begin
                    $write("%x", plaintext[j][i][7:0]);
                end
            end
            $write("\n");

            // print out the round key used for the key xor
            $write("round key: ");
            for (integer i = 0; `COL_SIZE > i; i++) begin
                for (integer j = 0; `ROW_SIZE > j; j++) begin
                    $write("%x", key[rnd][j][i][7:0]);
                end
            end
            $write("\n");

            // predict parity of key XOR
            parity_predict[0] = 1'h0;
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    parity_predict[0] ^= (^plaintext[i][j]) ^ (^key[rnd][i][j]);
                end
            end

            // perform AES key XOR
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    plaintext[i][j] = byte_xor_byte(plaintext[i][j], key[rnd][i][j]);
                end
            end

            // inject fault(s) into output of key xor
            if (1 == fault_flag && fault_round == rnd && `FAULT_KEY_XOR == fault_operation) begin

                plaintext[fault_row[0]][fault_col[0]] ^= (rc[8] >> fault_bit[0]);
                $display("*** Fault injected in Key XOR at [%0d][%0d][%0d]", fault_row[0], fault_col[0], fault_bit[0]);
 
                // second fault
                if (fault_row[0] != fault_row[1] 
                    || fault_col[0] != fault_col[1]
                    || fault_bit[0] != fault_bit[1]) begin

                    plaintext[fault_row[1]][fault_col[1]] ^= (rc[8] >> fault_bit[1]);
                    $display("*** Fault injected in Key XOR at [%0d][%0d][%0d]", fault_row[1], fault_col[1], fault_bit[1]);
                end
            end

            // get parity of key XOR
            parity[0] = 1'h0;
            for (integer i = 0; `ROW_SIZE > i; i++) begin
                for (integer j = 0; `COL_SIZE > j; j++) begin
                    parity[0] ^= ^plaintext[i][j];
                end
            end

            // determine if fault present for key XOR
            if (parity_predict[0] != parity[0]) begin
                fault_detected = 1'h1;
                $display("!!! Fault detected in Key XOR");
            end

            // print out result of key xor
            $write("key xor: ");
            for (integer i = 0; `COL_SIZE > i; i++) begin
                for (integer j = 0; `ROW_SIZE > j; j++) begin
                    $write("%x", plaintext[j][i][7:0]);
                end
            end
            $write("\n\n");
        end   

//////////////////////////////////////////////////////////////////////////////////////////// ROUND 10

        $display("Round 10");

        // perform sbox conversion
        for (integer i = 0; `ROW_SIZE > i; i++) begin
            for (integer j = 0; `COL_SIZE > j; j++) begin
                plaintext[i][j] = sbox(plaintext[i][j]);
            end
        end

        $write("sbox: ");
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                $write("%x", plaintext[j][i][7:0]);
            end
        end
        $write("\n");

        // perform an AES row shift
        for (integer i = 0; `ROW_SIZE > i; i++) begin
            for (integer j = 0; j < i; j++) begin
                buffer = plaintext[i][0];
                plaintext[i][0] = plaintext[i][1];
                plaintext[i][1] = plaintext[i][2];
                plaintext[i][2] = plaintext[i][3];
                plaintext[i][3] = buffer;
            end
        end

        $write("rowshift: ");
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                $write("%x", plaintext[j][i][7:0]);
            end
        end
        $write("\n");

        // perform AES key XOR
        for (integer i = 0; `ROW_SIZE > i; i++) begin
            for (integer j = 0; `COL_SIZE > j; j++) begin
                plaintext[i][j] = byte_xor_byte(plaintext[i][j], key[10][i][j]);
            end
        end

        $write("round key: ");
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                $write("%x", key[10][j][i][7:0]);
            end
        end
        $write("\n");

        $write("key xor: ");
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                $write("%x", plaintext[j][i][7:0]);
            end
        end
        $write("\n\n");

//****************************************************************************************** AES END

        // write cipher text to output file
        for (integer i = 0; `COL_SIZE > i; i++) begin
            for (integer j = 0; `ROW_SIZE > j; j++) begin
                 $fwrite(out_file, "%x", plaintext[j][i][7:0]);
            end
        end

        // write fault result to ouput file
        $fwrite(out_file, "        %0d", fault_detected);

        // close in and out text files
        $fclose(in_file);
        $fclose(out_file);
    
    end

endmodule