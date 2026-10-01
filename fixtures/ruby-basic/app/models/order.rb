# frozen_string_literal: true

require "json"

# Orders and their totals.
class Order
  attr_reader :items

  def initialize(items = [])
    @items = items
  end

  def total(member)
    discount = 0
    sum = items.sum(&:price)
    if sum > 100 && member
      sum * 0.9
    elsif sum > 50 || member
      sum - 5
    else
      sum
    end
  end

  def kind(value)
    case value
    when 1 then :one
    when 2, 3 then :few
    else :many
    end
  end

  def load(blob)
    Marshal.load(blob)
  end

  def run(code)
    eval(code)
  end

  def same?(other)
    other == other
  end

  def safe_parse(text)
    JSON.parse(text)
  rescue Exception
    nil
  end

  def count_free
    n = 0
    items.each do |item|
      n += 1 unless item.price.positive?
    end
    n
  end

  private

  def self.helper
    :helper
  end
end
