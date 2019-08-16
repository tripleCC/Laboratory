
# 作用域关键字
TOKENTYPED = 'down'
TOKENTYPEU = 'up'

# 操作关键字
TOKENTYPEW = 'west'
TOKENTYPEN = 'north'
TOKENTYPEE = 'east'
TOKENTYPES = 'south'

# 绘制像素数
TOKENTYPENUMBER = 'number'

# 操作关键字
OPERATORS = [TOKENTYPEW, TOKENTYPEN, TOKENTYPEE, TOKENTYPES]

# 作用域关键字（可以类比 c 语言大括号作用域 { }，没有成对就是语法错误）
SCOPES = [TOKENTYPED, TOKENTYPEU]

class Token
  attr_reader :type
  attr_reader :value

  def initialize(type, value)
    @type = type
    @value = value
  end
end

class Lexer
  attr_reader :pos
  attr_reader :current_char
  attr_reader :text

  def initialize(text)
    @pos = 0
    @text = text
    @current_char = text[@pos]
  end

  def get_next_token
    while !@current_char.nil?
      skip_whitespace()

      char = @current_char
      case char
      when "D"
        advance()
        return Token.new(TOKENTYPED, char)
      when "U"
        advance()
        return Token.new(TOKENTYPEU, char)
      when "W"
        advance()
        return Token.new(TOKENTYPEW, char)
      when "N"
        advance()
        return Token.new(TOKENTYPEN, char)
      when "E"
        advance()
        return Token.new(TOKENTYPEE, char)
      when "S"
        advance()
        return Token.new(TOKENTYPES, char)
      else
        return Token.new(TOKENTYPENUMBER, get_number) 
      end
    end
  end

  private

  def advance
    @pos += 1
    if @pos <= @text.length
      @current_char = @text[@pos]
    else
      @current_char = nil 
    end
  end

  def get_number
    result = ""
    while !@current_char.nil? && "0" <= @current_char && "9" >= @current_char
      result += @text[@pos]
      advance()
    end
    result
  end

  def skip_whitespace
    while @current_char == " " || @current_char == "\n"
      advance()
    end
  end
end

class AST
  def eval
    raise 'Abstract eval!'
  end
end

class DrawAST < AST 
  def initialize(programs)
    @programs = programs
  end

  def eval
    @programs.each(&:eval)
  end
end

class ProgramAST < AST
  def initialize(actions)
    @actions = actions
  end

  def eval
    puts "\npen down"
    @actions.each(&:eval)
    puts "pen up\n"
  end
end

class ActionAST < AST 
  def initialize(operator, number)
    @operator = operator
    @number = number
  end

  def eval
    puts "draw #{@operator.type} by #{@number.value}"
  end
end

class Parser
  def initialize(lexer) 
    @lexer = lexer
    @current_token = lexer.get_next_token()
  end

  def parse
    programs = []
    while !@current_token.nil? && SCOPES.include?(@current_token.type)
      programs << program()
    end
    DrawAST.new(programs.compact)
  end

  private

  def action
    operator = @current_token
    eat(@current_token.type)

    number = @current_token
    eat(TOKENTYPENUMBER)

    ActionAST.new(operator, number)
  end
  
  def program
    eat(TOKENTYPED)

    actions = []
    while !@current_token.nil? && OPERATORS.include?(@current_token.type)
      actions << action()
    end

    program = ProgramAST.new(actions)
    program if eat(TOKENTYPEU)
  end

  def eat(type)
    if @current_token.type == type
      @current_token = @lexer.get_next_token()
    else
      puts "Invalid syntax: #{@current_token.type}, did you mean? #{type}"
      false
    end
  end
end

class Interpreter
  def initialize(parser)
     @parser = parser
  end

  def interpret
     @parser.parse().eval()
  end
end

# 输入示例
# D U 可以类比 c 语言大括号作用域 { }，没有成对就是语法错误
input = <<-EOF
D
W 2
N 2
E 2
S 1
N 2
N 2
U

D
S 112
U

D 
W 2

EOF

# 解释器对应的 EBNF, 采用递归下降的方式解析
# program ::= D (actions)* U
# action ::= operator number
# operator ::= W | N | E | S

# 词法分析
lexer = Lexer.new(input)
# 语法分析
parser = Parser.new(lexer)
# 解析器
interpreter = Interpreter.new(parser)
# 解析描绘语法
interpreter.interpret()

