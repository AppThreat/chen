def handle(response, expected = :ok)
  case response
  in { status: :ok, data: { user: name } }
    puts "hello #{name}"
  in { status: ^expected, data: String } if expected == :ok
    expected.to_s
  in { status: Integer => code, data: String } if code < 400
    code.to_s
  in [first, *rest]
    rest
  in [*, middle, *]
    middle
  in Integer | String
    nil
  end
end
config in {name:}
value => other
