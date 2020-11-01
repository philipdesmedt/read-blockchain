# frozen_string_literal: true

require 'digest'

# Class to read in a single .dat file or all .dat files from the Bitcoin blockchain
class BlockchainReader
  attr_reader :directory, :files, :current_block, :unparsed_transactions, :blocks

  def initialize(directory: '/Users/philip/Library/Application Support/Bitcoin/blocks')
    @directory = directory
    @files = Dir.glob("#{directory}/blk*.dat")
  end

  def read_all
    files.each do |filename|
      read_block(filename)
    end
  end

  def read_block(filename)
    file = File.open(filename, 'rb')
    message_header = bin_to_hex(file.read(8))
    # https://learnmeabitcoin.com/technical/magic-bytes
    _magic_bytes = message_header[0...8]
    block_size = hex_to_dec(swap_little_endian(message_header[8...16]))

    block = bin_to_hex(file.read(block_size))
    @current_block = block
    version = block[0...8]
    previous_block = block[8...72]
    merkle_root = block[72...136]
    timestamp = block[136...144]
    bits = block[144...152]
    nonce = block[152...160]

    block_header = "#{version}#{previous_block}#{merkle_root}#{timestamp}#{bits}#{nonce}"
    block_hash = swap_alternative(bin_to_hex(Digest::SHA256.digest(Digest::SHA256.digest([block_header].pack('H*')))))
    puts "Found block: #{block_hash} [#{block_size} bytes]"

    # @unparsed_transactions = block[160..-1]
    # tx_array = parse_varint(unparsed_transactions)
    # transaction_count = hex_to_dec(swap_little_endian(tx_array[1]))
    # puts "Found #{transaction_count} transactions in the block"

    # @unparsed_transactions = block[(160 + tx_array[2])..-1]
    # transaction_pointer = 0
    # while unparsed_transactions[transaction_pointer]
    #   transaction_buffer = unparsed_transactions[transaction_pointer..(transaction_pointer + 7)]
    #   transaction_pointer += 8

    #   transaction_pointer += 32
    #   transaction_buffer = ''
    # end
  end

  private

  # Calculates the full variable integer and returns it
  # https://learnmeabitcoin.com/technical/varint
  def parse_varint(transactions)
    prefix = transactions[0..1]

    if prefix == 'fd'
      value = transactions[2..5]
      full = "#{prefix}#{value}"
      length = 6
    elsif prefix == 'fe'
      value = transactions[2..9]
      full = "#{prefix}#{value}"
      length = 10
    elsif prefix == 'ff'
      value = transactions[2..17]
      full = "#{prefix}#{value}"
      length = 18
    else
      value = prefix
      full = value
      length = 2
    end

    [full, value, length]
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

  def swap_little_endian(str)
    # https://en.wikipedia.org/wiki/Endianness
    # https://stackoverflow.com/questions/16077885/how-to-convert-to-big-endian-in-ruby
    [str].pack('H*').unpack('N*').pack('V*').unpack1('H*')
  end

  def swap_alternative(str)
    str.scan(/(..)/).flatten.reverse.join
  end
end
