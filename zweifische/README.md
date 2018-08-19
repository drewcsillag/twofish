# Zweifische

Ruby binding for C implementation of twofish from [@drewcsillag](https://github.com/drewcsillag)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'zweifische'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install zweifische

## Usage

All key length (256, 192, and 128 bit) is supported. Each respective class can be used directly.

to use:
```ruby
require "zweifische"

# ecb mode

# for 128 bit key (16 bytes)
key="0123456789123456"
tf = Zweifische::Cipher128ecb.new(key)
crypted_text = tf.encrypt("plain text to encrypt here")
```

to encrypt stream use `encrypt_update` for each chunks, then `encrypt_final` at the end of the stream.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/fudanchii/zweifische.
