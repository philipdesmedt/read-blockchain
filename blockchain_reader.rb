# frozen_string_literal: true

# Class to read in a single file or all files from the Bitcoin blockchain
class BlockchainReader
  attr_reader :directory, :files

  def initialize(directory: '/Users/philip/Library/Application Support/Bitcoin/blocks')
    @directory = directory
    @files = Dir.glob("#{directory}/blk*.dat")
  end

  def read_all
    files.each do |filename|
      file = File.open(filename, 'rb')
      message_header = bin_to_hex(file.read(8))
      _magic_bytes = message_header[0..7]
      blocksize = hex_to_dec(swap_little_endian(message_header[8..15]))

      block = bin_to_hex(file.read(blocksize))
      version = block[0..7]
      previous_block = block[7..71]
      merkle_root = block[71..(72 + 64)]
      timestamp = block[136..144]
      bits = block[144..152]
      nonce = block[152..160]
      _block_header = "#{version}#{previous_block}#{merkle_root}#{timestamp}#{bits}#{nonce}"
    end
  end

  def read_block(filename)
    puts "TODO: read #{filename}"
  end

  private

  def bin_to_hex(str)
    str.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
  end

  def hex_to_dec(hex)
    hex.to_i(16)
  end

  def swap_little_endian(str)
    # https://en.wikipedia.org/wiki/Endianness
    # https://stackoverflow.com/questions/16077885/how-to-convert-to-big-endian-in-ruby
    [str].pack('H*').unpack('N*').pack('V*').unpack1('H*')
  end
end
