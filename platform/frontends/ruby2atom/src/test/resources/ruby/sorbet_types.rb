# typed: strict
# frozen_string_literal: true

# Sorbet sig blocks, consumed by RubyProgramSummaryBuilder through the generator's `has_sig`
# fact (ruby_ast_gen 2.x): parameter and return types fill the program summary where JSON
# from older generators leaves `ANY`.
class Order
  extend T::Sig

  sig { params(amount: Integer, currency: String).returns(String) }
  def format(amount, currency)
    "#{currency} #{amount}"
  end

  sig { params(id: T.nilable(Integer)).returns(T.nilable(String)) }
  def find(id)
    nil
  end

  sig { params(other: T.untyped).returns(T.any(Integer, String)) }
  def merge(other)
    other
  end

  sig { abstract.void }
  def validate; end

  # The negative case: no preceding sig, so the summary keeps the method untyped.
  def untyped_method(payload)
    payload
  end

  sig { params(label: String).void }
  def self.log!(label)
    puts label
  end

  # Sorbet accepts a trailing runtime-check chain and a WithoutRuntime receiver; both are
  # signatures, and the generator marks the defs that follow them.
  sig { params(count: Integer).returns(String) }.checked(:never)
  def checked_form(count)
    count.to_s
  end

  T::Sig::WithoutRuntime.sig { returns(Integer) }
  def without_runtime
    1
  end
end
