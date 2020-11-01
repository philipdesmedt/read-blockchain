# frozen_string_literal: true

require 'digest'

# Class to read in a single .dat file or all .dat files from the Bitcoin blockchain
class BlockchainReader
  attr_reader :directory, :files, :block, :blocks

  def initialize(directory: '/Users/philip/Library/Application Support/Bitcoin/blocks')
    @directory = directory
    @files = Dir.glob("#{directory}/blk*.dat")
  end

  def read_all
    files.each do |filename|
      read_file(filename)
    end
  end

  def read_file(filename)
    file = File.open(filename, 'rb')
    # https://learnmeabitcoin.com/technical/blkdat
    message_header = bin_to_hex(file.read(8))
    return if message_header.nil?

    read_block(file, message_header)
  end

  def read_block(file, message_header)
    # https://learnmeabitcoin.com/technical/magic-bytes
    _magic_bytes = message_header[0...8]
    block_size = hex_to_dec(swap_alternative(message_header[8...16]))

    @block = bin_to_hex(file.read(block_size))
    block_header = calculate_block_header(block)
    block_hash = swap_alternative(bin_to_hex(Digest::SHA256.digest(Digest::SHA256.digest([block_header].pack('H*')))))
    puts "Found block with hash: #{block_hash} [#{block_size} bytes]"

    transaction_data = block[160..-1]
    tx_array = parse_varint(transaction_data)
    transaction_count = hex_to_dec(swap_alternative(tx_array[1]))
    puts "#{transaction_count} transactions in the block"
    puts 'Parsing transactions...'

    unparsed_transactions = block[(160 + tx_array[0].length)..-1]
    transaction_pointer = 0
    while unparsed_transactions[transaction_pointer]
      _version = unparsed_transactions[transaction_pointer...(transaction_pointer + 8)]
      transaction_pointer += 12 # there is some unknown data '0001', so skip it
      input_counts = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
      input_count = hex_to_dec(input_counts[1])
      puts "\tNumber of inputs: #{input_count}"
      transaction_pointer += input_counts[0].length

      input_count.times do |_x|
        tx_id = unparsed_transactions[transaction_pointer...(transaction_pointer + 64)]
        puts "\t\tTransaction ID: #{tx_id}"
        transaction_pointer += 64

        vout = unparsed_transactions[transaction_pointer...(transaction_pointer + 8)]
        puts "\t\tSelected VOut: #{vout}"
        transaction_pointer += 8

        parsed_scriptsig_size = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
        puts "\t\tscriptSig size: #{parsed_scriptsig_size[1]} bytes"
        transaction_pointer += parsed_scriptsig_size[0].length

        size = hex_to_dec(parsed_scriptsig_size[1]) * 2
        script_sig = unparsed_transactions[transaction_pointer...(transaction_pointer + size)]
        puts "\t\tscripSig: #{script_sig}"
        transaction_pointer += size

        sequence = unparsed_transactions[transaction_pointer...(transaction_pointer + 8)]
        puts "\t\tSequence: #{sequence}"
        transaction_pointer += 8
      end

      output_counts = parse_varint(unparsed_transactions[transaction_pointer...(transaction_pointer + 18)])
      output_count = hex_to_dec(output_counts[1])
      puts "\tNumber of outputs: #{output_count}"
      transaction_pointer += output_counts[0].length

      output_count.times do |_x|
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

      locktime = unparsed_transactions[transaction_pointer...(transaction_pointer + 8)]
      puts "\tLocktime: #{locktime}"

      transaction_pointer += 10_000_000
      false
    end

    false
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
      value = input[2...6]
      full = "#{prefix}#{value}"
    elsif prefix == 'fe'
      value = input[2...10]
      full = "#{prefix}#{value}"
    elsif prefix == 'ff'
      value = input[2...18]
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
