//
//  main.m
//  Interpreter
//
//  Created by tripleCC on 7/18/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
//#include <ctype.h>
//#import <Foundation/Foundation.h>
//
//typedef enum : NSUInteger {
//    TokenTypeInterger,
//    TokenTypePlus,
//    TokenTypeEOF,
//    TokenTypeSubtract,
//    TokenTypeMul,
//    TokenTypeDiv,
//    TokenTypeLP,
//    TokenTypeRP,
//} TokenType;
//
//@interface Token : NSObject  {
//    @public
//    TokenType _type;
//    id _value;
//}
//@end
//@implementation Token
//- (NSString *)description {
//    return [NSString stringWithFormat:@"Token({%@}, {%@})", _value, @(_type)];
//}
//
//- (instancetype)initWithType:(TokenType)type value:(id)value {
//    self = [super init];
//
//    _value = value;
//    _type = type;
//
//    return self;
//}
//@end
//
//@interface Lexer : NSObject {
//    NSString *_text;
//    NSInteger _pos;
//    char _currentChar;
//}
//- (instancetype)initWithText:(NSString *)text;
//@end
//@implementation Lexer
//- (instancetype)initWithText:(NSString *)text {
//    self = [super init];
//
//    _text = text;
//    _pos = 0;
//    _currentChar = [text characterAtIndex:_pos];
//
//    return self;
//}
//
//- (void)advance {
//    _pos++;
//    if (_pos < _text.length) {
//        _currentChar = [_text characterAtIndex:_pos];
//    } else {
//        _currentChar = EOF;
//    }
//}
//
//- (void)skipWhitespace {
//    while (_currentChar != EOF && _currentChar == ' ') {
//        [self advance];
//    }
//}
//
//- (NSInteger)integer {
//    NSInteger r = 0;
//    while (_currentChar != EOF && isdigit(_currentChar)) {
//        r *= 10;
//        r += _currentChar - '0';
//        [self advance];
//    }
//    return r;
//}
//
//- (Token *)getNextToken {
//    while (_currentChar != EOF) {
//        [self skipWhitespace];
//
//        if (isdigit(_currentChar)) {
//            return [[Token alloc] initWithType:TokenTypeInterger value:@([self integer])];
//        }
//
//        if (_currentChar == '*') {
//            [self advance];
//            return [[Token alloc] initWithType:TokenTypeMul value:@"*"];
//        }
//
//        if (_currentChar == '/') {
//            [self advance];
//            return [[Token alloc] initWithType:TokenTypeDiv value:@"/"];
//        }
//
//        if (_currentChar == '-') {
//            [self advance];
//            return [[Token alloc] initWithType:TokenTypeSubtract value:@"-"];
//        }
//
//        if (_currentChar == '+') {
//            [self advance];
//            return [[Token alloc] initWithType:TokenTypePlus value:@"+"];
//        }
//
//        if (_currentChar == '(') {
//            [self advance];
//            return [[Token alloc] initWithType:TokenTypeLP value:@"("];
//        }
//
//        if (_currentChar == ')') {
//            [self advance];
//            return [[Token alloc] initWithType:TokenTypeRP value:@")"];
//        }
//
//        [NSException raise:@"invalid syntax" format:@""];
//    }
//
//    return [[Token alloc] initWithType:TokenTypeEOF value:nil];
//}
//@end
//
//
//@interface AST : NSObject
//- (NSInteger)eval;
//@end
//@implementation AST
//- (NSInteger)eval {
//    return 0;
//}
//@end
//
//@interface BinOp : AST {
//    AST *_left;
//    AST *_right;
//    char _op;
//}
//- (instancetype)initWithLeft:(AST *)left right:(AST *)right op:(char)op;
//@end
//@implementation BinOp
//- (instancetype)initWithLeft:(AST *)left right:(AST *)right op:(char)op {
//    self = [super init];
//    _left = left;
//    _right = right;
//    _op = op;
//    return self;
//}
//
//- (NSInteger)eval {
//    switch (_op) {
//        case '-': return [_left eval] - [_right eval];
//        case '+': return [_left eval] + [_right eval];
//        case '*': return [_left eval] * [_right eval];
//        case '/': return [_left eval] / [_right eval];
//    }
//    return 0;
//}
//
//- (NSString *)description {
//    return [NSString stringWithFormat:@"(%c %@ %@)", _op, _left, _right];
//}
//@end
//
//@interface Num : AST {
//    Token *_token;
//    NSInteger _value;
//}
//- (instancetype)initWithToken:(Token *)token value:(NSInteger)value;
//@end
//
//@implementation Num
//- (instancetype)initWithToken:(Token *)token value:(NSInteger)value {
//    self = [super init];
//    _token = token;
//    _value = value;
//    return self;
//}
//
//- (NSInteger)eval {
//    return _value;
//}
//
//- (NSString *)description {
//    return @(_value).stringValue;
//}
//@end
//
//@interface UnaryOp : AST {
//    Token *_token;
//    AST *_right;
//}
//- (instancetype)initWithToken:(Token *)token right:(AST *)right;
//@end
//
//@implementation UnaryOp
//- (instancetype)initWithToken:(Token *)token right:(AST *)right {
//    self = [super init];
//    _token = token;
//    _right = right;
//    return self;
//}
//
//- (NSInteger)eval {
//    switch (_token->_type) {
//        case TokenTypeSubtract: return -[_right eval];
//        case TokenTypePlus: return +[_right eval];
//        default: return 0;
//    }
//}
//@end
//
//@interface Parser : NSObject {
//    Lexer *_lexer;
//    Token *_currentToken;
//}
//- (instancetype)initWithLexer:(Lexer *)lexer;
//@end
//@implementation Parser
//- (instancetype)initWithLexer:(Lexer *)lexer {
//    self = [super init];
//    _lexer = lexer;
//    _currentToken = [_lexer getNextToken];
//    return self;
//}
//
//
//- (void)eat:(TokenType)type {
//    if (_currentToken->_type == type) {
//        _currentToken = [_lexer getNextToken];
//    } else {
//        [NSException raise:@"invalid syntax" format:@""];
//    }
//}
//
//- (AST *)factor {
//    Token *t = _currentToken;
//
//    if (t->_type == TokenTypeSubtract ||
//        t->_type == TokenTypePlus) {
//        [self eat:t->_type];
//        return [[UnaryOp alloc] initWithToken:t right:[self factor]];
//    } else if (t->_type == TokenTypeLP) {
//        [self eat:TokenTypeLP];
//        AST *r = [self expr];
//        [self eat:TokenTypeRP];
//        return r;
//    } else {
//        [self eat:TokenTypeInterger];
//        return [[Num alloc] initWithToken:t value:[t->_value integerValue]];
//    }
//}
//
//- (AST *)term {
//    AST *r = [self factor];
//    while (_currentToken->_type == TokenTypeMul ||
//           _currentToken->_type == TokenTypeDiv) {
//
//        Token *t = _currentToken;
//
//        [self eat:_currentToken->_type];
//
//        if (t->_type == TokenTypeMul) {
//            r = [[BinOp alloc] initWithLeft:r right:[self factor] op:'*'];
//        } else {
//            r = [[BinOp alloc] initWithLeft:r right:[self factor] op:'/'];
//        }
//    }
//
//    return r;
//}
//
//- (AST *)expr {
//    AST *r = [self term];
//    while (_currentToken->_type == TokenTypeSubtract ||
//           _currentToken->_type == TokenTypePlus) {
//
//        Token *t = _currentToken;
//
//        [self eat:_currentToken->_type];
//
//        if (t->_type == TokenTypeSubtract) {
//            r = [[BinOp alloc] initWithLeft:r right:[self term] op:'-'];
//        } else {
//            r = [[BinOp alloc] initWithLeft:r right:[self term] op:'+'];
//        }
//    }
//
//    return r;
//}
//@end
//
//@interface Interpreter : NSObject {
//    Parser *_parser;
//}
//- (instancetype)initWithParser:(Parser *)parser;
//- (NSInteger)interpret;
//@end
//
//@implementation Interpreter
//- (instancetype)initWithParser:(Parser *)parser {
//    self = [super init];
//
//    _parser = parser;
//
//    return self;
//}
//
//- (NSInteger)interpret {
//    return [[_parser expr] eval];
//}
//@end
//
////
//// expr ::= term ((SUB | ADD) term)*
//// term ::= factor ((MUL | DIV) factor)*
//// factor ::= (SUB | ADD) factor | INTEGER | LP expr RP
//
//int main(int argc, const char * argv[]) {
//    @autoreleasepool {
//        Lexer *lexer = [[Lexer alloc] initWithText:@"-2 + -3 * 5"];
//        Parser *parser = [[Parser alloc] initWithLexer:lexer];
//        Interpreter *intepreter = [[Interpreter alloc] initWithParser:parser];
//        NSLog(@"%ld", [intepreter interpret]);
//        //        NSLog(@"%@", [parser expr]);
//        // insert code here...
//    }
//    return 0;
//}
