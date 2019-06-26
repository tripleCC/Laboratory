import Foundation

try NSRegularExpression(pattern: "\\s*((//.*)|([0-9]+)|(\"(\\\\\"|\\\\\\\\|\\\\n|[^\"])*\")|[A-z_a-z][A-Z_a-z0-9]*|==|<=|>=|&&|\\|\\||\\p{Punct})?", options: .caseInsensitive)

class Token {
    static let EOF = Token(-1)
    static let EOL = "\\n"
    private var lineNumber: Int
    init(_ line: Int) {
        self.lineNumber = line
    }
    func getLineNumber() -> Int {
        return lineNumber
    }
    func isIdentifier() -> Bool {
        return false
    }
    func isNumber() -> Bool {
        return false
    }
    func isString() -> Bool {
        return false
    }
    func getNumber() -> Int {
        return -1;
    }
    func getText() -> String {
        return ""
    }
}

class Lexer {
    let regex = "\\s*((//.*)|([0-9]+)|(\"(\\\\\"|\\\\\\\\|\\\\n|[^\"])*\")|[A-z_a-z][A-Z_a-z0-9]*|==|<=|>=|&&|\\|\\||\\p{Punct})?"
    var queue = Array<Token>()
    var hasMore: Bool = true
    var contents: String = ""
    
    init(url: URL) {
        if let c = try? String(contentsOf: url) {
            contents = c
        }
    }
}
