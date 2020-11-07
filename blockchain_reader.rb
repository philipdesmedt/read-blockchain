# frozen_string_literal: true

require 'digest'

# Class to read in a single .dat file or all .dat files from the Bitcoin blockchain
class BlockchainReader
  attr_reader :directory, :files, :block_hashes

  def initialize(directory: '/Users/philip/Library/Application Support/Bitcoin/blocks')
    @directory = directory
    @files = Dir.glob("#{directory}/blk*.dat")
    @block_hashes = []
  end

  def read_all
    files.each do |filename|
      read_file(filename)
    end
  end

  def read_file(filename)
    file = File.open(filename, 'rb')
    # https://learnmeabitcoin.com/technical/blkdat
    raw_header = file.read(8)

    loop do
      break if raw_header.nil?

      message_header = bin_to_hex(raw_header)
      transaction_pointer = read_block(file, message_header)
      puts "Next block at #{transaction_pointer}"
      raw_header = file.read(8)
    end
  end

  def read_block(file, message_header)
    # https://learnmeabitcoin.com/technical/magic-bytes
    _magic_bytes = message_header[0...8]
    block_size = hex_to_dec(swap_alternative(message_header[8...16]))

    block = bin_to_hex(file.read(block_size))
    block_header = calculate_block_header(block)
    block_hash = swap_alternative(bin_to_hex(Digest::SHA256.digest(Digest::SHA256.digest([block_header].pack('H*')))))
    puts "Found block with hash: #{block_hash} [#{block_size} bytes]"
    block_hashes << block_hash

    transaction_data = block[160..-1]
    tx_array = parse_varint(transaction_data)
    transaction_count = hex_to_dec(swap_alternative(tx_array[1]))
    puts "#{transaction_count} transactions in the block"
    puts 'Parsing transactions...'

    unparsed_transactions = block[(160 + tx_array[0].length)..-1]
    transaction_pointer = 0
    tx_index = 0
    # https://learnmeabitcoin.com/technical/transaction-data
    # https://developer.bitcoin.org/reference/transactions.html
    while unparsed_transactions[transaction_pointer]
      tx_index += 1
      puts "Starting transaction #{tx_index} of block with hash #{block_hash}"
      puts "Approximate data: #{unparsed_transactions[transaction_pointer...(transaction_pointer + 10000)]}"
      _version = unparsed_transactions[transaction_pointer...(transaction_pointer + 8)]
      transaction_pointer += 8 # there is some unknown data '0001', so skip it
      witness_program = unparsed_transactions[transaction_pointer...(transaction_pointer + 4)]
      transaction_pointer += 4 if %w[0001 0000].include?(witness_program)

      input_counts = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
      input_count = hex_to_dec(input_counts[1])
      puts "\tNumber of inputs: #{input_count}"
      transaction_pointer += input_counts[0].length
      coinbase_transaction = false
      vout = -99
      extract_witness_data = false

      input_count.times do |i|
        tx_id = unparsed_transactions[transaction_pointer...(transaction_pointer + 64)]
        puts "\t\tPrevious Transaction Hash: #{tx_id} (#{swap_alternative(tx_id)})"
        transaction_pointer += 64
        coinbase_transaction = (tx_id == '0' * 64) if i.zero?

        vout = unparsed_transactions[transaction_pointer...(transaction_pointer + 8)]
        puts "\t\tSelected VOut: #{vout}"
        transaction_pointer += 8

        parsed_scriptsig_size = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
        puts "\t\tscriptSig size: #{parsed_scriptsig_size[1]} bytes"
        transaction_pointer += parsed_scriptsig_size[0].length

        size = hex_to_dec(parsed_scriptsig_size[1]) * 2
        script_sig = unparsed_transactions[transaction_pointer...(transaction_pointer + size)]
        puts "\t\tscriptSig: #{script_sig}"
        transaction_pointer += size
        # OP_PUSHBYTES_22 type == 'P2SH' && hex_to_dec(swap_alternative(vout)) == i
        extract_witness_data = true if %w[16 22].include?(script_sig[0...2]) || script_sig.empty?

        sequence = unparsed_transactions[transaction_pointer...(transaction_pointer + 8)]
        puts "\t\tSequence: #{sequence}"
        transaction_pointer += 8
      end

      output_counts = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
      output_count = hex_to_dec(output_counts[1])
      puts "\tNumber of outputs: #{output_count}"
      transaction_pointer += output_counts[0].length

      output_count.times do
        amount = unparsed_transactions[transaction_pointer...(transaction_pointer + 16)]
        puts "\t\tAmount: #{swap_alternative(amount).to_i(16)} satoshi"
        transaction_pointer += 16

        parsed_scriptpubkey_size = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
        puts "\t\tscriptPubKey size: #{parsed_scriptpubkey_size[1]} bytes"
        transaction_pointer += parsed_scriptpubkey_size[0].length

        size = hex_to_dec(parsed_scriptpubkey_size[1]) * 2
        script_pub_key = unparsed_transactions[transaction_pointer...(transaction_pointer + size)]
        puts "\t\tscriptPubKey: #{script_pub_key}"
        transaction_pointer += size
        puts "\n"
      end

      if coinbase_transaction
        no_of_parts = hex_to_dec(unparsed_transactions[transaction_pointer...(transaction_pointer + 2)])
        transaction_pointer += 2
        parsed_length = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
        length = hex_to_dec(parsed_length[1]) * 2
        transaction_pointer += parsed_length[0].length

        witness_data = unparsed_transactions[transaction_pointer...(transaction_pointer + length)]
        puts "\tThis is a coinbase transaction with witness data #{witness_data}"
        transaction_pointer += length
      end

      if extract_witness_data
        puts "\tThis is a P2SH or SegWit V0 transaction. Extracting witness data..."
        puts "\t\tWitness"
        input_count.times do |i|
          no_of_parts = hex_to_dec(unparsed_transactions[transaction_pointer...(transaction_pointer + 2)])
          transaction_pointer += 2
          puts "Extracting witness data for input count #{i + 1} which has #{no_of_parts} parts"

          no_of_parts.times do |_x|
            parsed_length = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
            length = hex_to_dec(parsed_length[1]) * 2
            transaction_pointer += parsed_length[0].length

            data = unparsed_transactions[transaction_pointer...(transaction_pointer + length)]
            transaction_pointer += length
            puts "\t\t#{data}"
          end
        end
      end

      locktime = unparsed_transactions[transaction_pointer...(transaction_pointer + 8)]
      puts "\tLocktime: #{locktime}\n\n"
      transaction_pointer += 8
    end

    transaction_pointer
  end

  private

  # https://learnmeabitcoin.com/technical/block-header
  def calculate_block_header(block)
    version = block[0...8]
    previous_block = block[8...72]
    merkle_root = block[72...136]
    timestamp = block[136...144]
    bits = block[144...152]
    nonce = block[152...160]

    "#{version}#{previous_block}#{merkle_root}#{timestamp}#{bits}#{nonce}"
  end

  # Calculates the full variable integer and returns it
  # https://learnmeabitcoin.com/technical/varint
  def parse_varint(input)
    prefix = input[0...2]

    if prefix == 'fd'
      value = swap_alternative(input[2...6])
      full = "#{prefix}#{value}"
    elsif prefix == 'fe'
      value = swap_alternative(input[2...10])
      full = "#{prefix}#{value}"
    elsif prefix == 'ff'
      value = swap_alternative(input[2...18])
      full = "#{prefix}#{value}"
    else
      value = prefix
      full = value
    end

    [full, value]
  end

  def bin_to_hex(str)
    str.unpack1('H*')
  end

  def hex_to_dec(hex)
    hex.to_i(16)
  end

  def hex_to_bin(hex)
    # ['DEADBEEF'].pack('H*').unpack('B*').first
    hex.hex.to_s(2).rjust(hex.size * 4, '0')
  end

  def hex_to_ascii(hex)
    [hex].pack('H*')
  end

  def swap_alternative(str)
    str.scan(/(..)/).flatten.reverse.join
  end
end
