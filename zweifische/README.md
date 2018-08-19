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

Currently the only supported key length is 256bit.

to use:
```ruby
require "zweifische"

# ecb mode

# key should be 16, 24, or 32 bytes length (will be padded with zero bytes if less than 32 bytes)
key="0123456789123456"
tf = Zweifische::Cipher256ecb.new(key)
crypted_text = tf.encrypt_final("more text here")
```

to encrypt stream use `encrypt_update` for each chunks, then `encrypt_final` at the end of the stream.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/fudanchii/zweifische.
