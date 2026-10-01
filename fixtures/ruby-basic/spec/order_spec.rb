require_relative "../app/models/order"

RSpec.describe Order do
  it "sums prices" do |example|
    expect(Order.new.total(false)).to eq(0)
  end
end
