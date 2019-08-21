//
//  main.m
//  Interpreter
//
//  Created by tripleCC on 7/18/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#include <ctype.h>
#import <Foundation/Foundation.h>

NSMutableDictionary *variablePool = nil;


@interface Symbol : NSObject {
@public
    NSString *_name;
    id _type;
}
- (instancetype)initWithName:(NSString *)name type:(id)type;
@end
@interface SymbolTable : NSObject {
    NSMutableDictionary *_symbolTable;
}
- (void)define:(Symbol *)s;
- (Symbol *)lookup:(NSString *)n;
@end


@interface VarSymbol : Symbol
@end

SymbolTable *symTable = nil;

typedef enum : NSUInteger {
    TokenTypePlus,
    TokenTypeEOF,
    TokenTypeMINUS,
    TokenTypeMul,
    TokenTypeLP,
    TokenTypeRP,
    TokenTypeASSIGN,
    TokenTypeSEMI,
    TokenTypeDOT,
    TokenTypeID,
    TokenTypeBEGIN,
    TokenTypeEND,
    TokenTypePROGRAM,
    TokenTypeCOMMA,
    TokenTypeCOLON,
    TokenTypeINTEGERDIV,
    TokenTypeFLOATDIV,
    TokenTypeINTEGERCONST,
    TokenTypeREALCONST,
    TokenTypeINTEGER,
    TokenTypeREAL,
    TokenTypeVAR,
} TokenType;

@interface Token : NSObject  {
    @public
    TokenType _type;
    id _value;
}
@end
@implementation Token
- (NSString *)description {
    return [NSString stringWithFormat:@"Token({%@}, {%@})", _value, @(_type)];
}

- (instancetype)initWithType:(TokenType)type value:(id)value {
    self = [super init];
    
    _value = value;
    _type = type;
    
    return self;
}
@end

@interface Lexer : NSObject {
    NSString *_text;
    NSInteger _pos;
    char _currentChar;
}
- (instancetype)initWithText:(NSString *)text;
@end
@implementation Lexer
- (instancetype)initWithText:(NSString *)text {
    self = [super init];
    
    _text = text;
    _pos = 0;
    _currentChar = [text characterAtIndex:_pos];
    
    return self;
}

- (void)advance {
    _pos++;
    if (_pos < _text.length) {
        _currentChar = [_text characterAtIndex:_pos];
    } else {
        _currentChar = EOF;
    }
}

- (void)skipWhitespace {
    while (_currentChar != EOF && _currentChar == ' ') {
        [self advance];
    }
}

- (void)skipComment {
    while (_currentChar != '}') {
        [self advance];
    }
    [self advance];
}

- (char)peek {
    int idx = (int)_pos + 1;
    if (idx < _text.length) {
        return [_text characterAtIndex:idx];
    }
    return EOF;
}

- (Token *)_id {
    char name[128] = {0};
    for (int i = 0; _currentChar != EOF && (isalnum(_currentChar) || _currentChar == '_'); i++) {
        name[i] = _currentChar;
        [self advance];
    }
    NSString *ocName = [NSString stringWithCString:name encoding:NSUTF8StringEncoding];
    ocName = [ocName lowercaseString];
    
    if ([ocName isEqualToString:@"begin"]) {
        return [[Token alloc] initWithType:TokenTypeBEGIN value:ocName];
    } else if ([ocName isEqualToString:@"end"]) {
        return [[Token alloc] initWithType:TokenTypeEND value:ocName];
    } else if ([ocName isEqualToString:@"div"]) {
        return [[Token alloc] initWithType:TokenTypeINTEGERDIV value:ocName];
    } else if ([ocName isEqualToString:@"program"]) {
        return [[Token alloc] initWithType:TokenTypePROGRAM value:ocName];
    } else if ([ocName isEqualToString:@"integer"]) {
        return [[Token alloc] initWithType:TokenTypeINTEGER value:ocName];
    } else if ([ocName isEqualToString:@"real"]) {
        return [[Token alloc] initWithType:TokenTypeREAL value:ocName];
    } else if ([ocName isEqualToString:@"var"]) {
        return [[Token alloc] initWithType:TokenTypeVAR value:ocName];
    }
    
    return [[Token alloc] initWithType:TokenTypeID value:ocName];
}

- (NSInteger)integer {
    NSInteger r = 0;
    while (_currentChar != EOF && isdigit(_currentChar)) {
        r *= 10;
        r += _currentChar - '0';
        [self advance];
    }
    return r;
}


- (Token *)number {
    NSInteger r = [self integer];
    if (_currentChar == '.') {
        [self advance];
        NSInteger f = [self integer];
        return [[Token alloc] initWithType:TokenTypeREALCONST value:@([[NSString stringWithFormat:@"%ld.%ld", r, f] floatValue])];
    }
    return [[Token alloc] initWithType:TokenTypeINTEGERCONST value:@(r)];
}

- (Token *)getNextToken {
    while (_currentChar != EOF) {
        [self skipWhitespace];
        
        if (_currentChar == '{') {
            [self advance];
            [self skipComment];
            continue;
        }
        
        if (isdigit(_currentChar)) {
            return [self number];
        }
        
        if (isalpha(_currentChar) || _currentChar == '_') {
            return [self _id];
        }
        
        if (_currentChar == ':' && [self peek] == '=') {
            [self advance];
            [self advance];
            return [[Token alloc] initWithType:TokenTypeASSIGN value:@":="];
        }
        
        if (_currentChar == ',') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeCOMMA value:@","];
        }
        
        if (_currentChar == ':') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeCOLON value:@":"];
        }
        
        if (_currentChar == ';') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeSEMI value:@";"];
        }
        
        if (_currentChar == '.') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeDOT value:@"."];
        }
        
        if (_currentChar == '*') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeMul value:@"*"];
        }
        
        if (_currentChar == '/') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeFLOATDIV value:@"/"];
        }
        
        if (_currentChar == '-') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeMINUS value:@"-"];
        }
        
        if (_currentChar == '+') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypePlus value:@"+"];
        }
        
        if (_currentChar == '(') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeLP value:@"("];
        }
        
        if (_currentChar == ')') {
            [self advance];
            return [[Token alloc] initWithType:TokenTypeRP value:@")"];
        }
        
        [NSException raise:@"invalid syntax" format:@"%c", _currentChar];
    }
    
    return [[Token alloc] initWithType:TokenTypeEOF value:nil];
}
@end


@interface AST : NSObject
- (NSInteger)eval;
@end
@implementation AST
- (NSInteger)eval {
    return 0;
}
@end

@interface Program : AST {
    NSString *_name;
    AST *_block;
}
- (instancetype)initWithName:(NSString *)name block:(AST *)block;
@end

@implementation Program
- (instancetype)initWithName:(NSString *)name block:(AST *)block {
    self = [super init];
    _name = name;
    _block = block;
    return self;
}

- (NSInteger)eval {
    return [_block eval];
}
@end

    @interface Block : AST {
    NSArray *_declarations;
    AST *_compoundStatement;
}
- (instancetype)initWithDeclarations:(NSArray *)declarations compoundStatement:(AST *)compoundStatement;
@end

@implementation Block
- (instancetype)initWithDeclarations:(NSArray *)declarations compoundStatement:(AST *)compoundStatement {
    self = [super init];
    _declarations = declarations;
    _compoundStatement = compoundStatement;
    return self;
}

- (NSInteger)eval {
    [_declarations enumerateObjectsUsingBlock:^(AST *obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [obj eval];
    }];
    [_compoundStatement eval];
    return 0;
}
@end

@interface Type : AST {
    @public
    Token *_token;
    id _value;
}
- (instancetype)initWithToken:(Token *)token;
@end


@interface Var : AST {
@public
    Token *_token;
}
- (instancetype)initWithToken:(Token *)token;
@end

@interface VarDecl : AST {
    Var *_var;
    Type *_type;
}
- (instancetype)initWithType:(Type *)type var:(Var *)var;
@end

@implementation VarDecl
- (instancetype)initWithType:(Type *)type var:(Var *)var {
    self = [super init];
    _var = var;
    _type = type;
    return self;
}

- (NSInteger)eval {
    Symbol *s = [symTable lookup:_type->_value];
    NSLog(@"%@", _type->_value);
    [symTable define:[[VarSymbol alloc] initWithName:_var->_token->_value type:s]];
    return 0;
}
@end


@implementation Type
- (instancetype)initWithToken:(Token *)token {
    self = [super init];
    _token = token;
    _value = token->_value;
    return self;
}
@end

@interface BinOp : AST {
    AST *_left;
    AST *_right;
    Token *_op;
}
- (instancetype)initWithLeft:(AST *)left right:(AST *)right op:(Token *)op;
@end
@implementation BinOp
- (instancetype)initWithLeft:(AST *)left right:(AST *)right op:(Token *)op {
    self = [super init];
    _left = left;
    _right = right;
    _op = op;
    return self;
}

- (NSInteger)eval {
    switch (_op->_type) {
        case TokenTypeMINUS: return [_left eval] - [_right eval];
        case TokenTypePlus: return [_left eval] + [_right eval];
        case TokenTypeMul: return [_left eval] * [_right eval];
        case TokenTypeFLOATDIV: return (float)[_left eval] / (float)[_right eval];
        case TokenTypeINTEGERDIV: return [_left eval] / [_right eval];
        default: break;
    }
    return 0;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"(%@ %@ %@)", _op->_value, _left, _right];
}
@end

@interface Num : AST {
    Token *_token;
    NSInteger _value;
}
- (instancetype)initWithToken:(Token *)token value:(NSInteger)value;
@end

@implementation Num
- (instancetype)initWithToken:(Token *)token value:(NSInteger)value {
    self = [super init];
    _token = token;
    _value = value;
    return self;
}

- (NSInteger)eval {
    return _value;
}

- (NSString *)description {
    return @(_value).stringValue;
}
@end

@interface UnaryOp : AST {
    Token *_token;
    AST *_right;
}
- (instancetype)initWithToken:(Token *)token right:(AST *)right;
@end

@implementation UnaryOp
- (instancetype)initWithToken:(Token *)token right:(AST *)right {
    self = [super init];
    _token = token;
    _right = right;
    return self;
}

- (NSInteger)eval {
    switch (_token->_type) {
        case TokenTypeMINUS: return -[_right eval];
        case TokenTypePlus: return +[_right eval];
        default: return 0;
    }
}
@end

@interface Compound : AST {
    @public
    NSMutableArray *_children;
}
@end
@implementation Compound
- (instancetype)init
{
    self = [super init];
    if (self) {
        _children = [NSMutableArray array];
    }
    return self;
}
- (NSInteger)eval {
    __block NSInteger r  = 0;
    [_children enumerateObjectsUsingBlock:^(AST *obj, NSUInteger idx, BOOL * _Nonnull stop) {
        r += [obj eval];
    }];
    return r;
}
@end


@interface Assign : AST {
    Var *_left;
    char _op;
    AST *_right;
}
- (instancetype)initWithLeft:(Var *)left right:(AST *)right op:(char)op;
@end
@implementation Assign
- (instancetype)initWithLeft:(Var *)left right:(AST *)right op:(char)op {
    self = [super init];
    _left = left;
    _right = right;
    _op = op;
    return self;
}

- (NSInteger)eval {
    if (![symTable lookup:_left->_token->_value]) {
        [NSException raise:@"未定义" format:@"%@", _left->_token->_value];
    }
    variablePool[_left->_token->_value] = @([_right eval]);
    return 0;
}
@end

@implementation Var
- (instancetype)initWithToken:(Token *)token {
    self = [super init];
    _token = token;
    return self;
}

- (NSInteger)eval {
    if (![symTable lookup:_token->_value]) {
        [NSException raise:@"未定义" format:@"%@", _token->_value];
    }
    return [variablePool[_token->_value] integerValue];
}
@end

@interface NoOp : AST
@end
@implementation NoOp
@end

@interface Parser : NSObject {
    Lexer *_lexer;
    Token *_currentToken;
}
- (instancetype)initWithLexer:(Lexer *)lexer;
@end
@implementation Parser
- (instancetype)initWithLexer:(Lexer *)lexer {
    self = [super init];
    _lexer = lexer;
    _currentToken = [_lexer getNextToken];
    return self;
}


- (void)eat:(TokenType)type {
    if (_currentToken->_type == type) {
        _currentToken = [_lexer getNextToken];
        NSLog(@"%@", _currentToken);
    } else {
        [NSException raise:@"invalid syntax" format:@"%@", _currentToken->_value];
    }
}

- (AST *)variable {
    AST *r = [[Var alloc] initWithToken:_currentToken];
    [self eat:TokenTypeID];
    return r;
}

- (AST *)assignment_statement {
    AST *left = [self variable];
    [self eat:TokenTypeASSIGN];
    AST *right = [self expr];
    return [[Assign alloc] initWithLeft:(Var *)left right:right op:'='];
}

- (AST *)empty {
    return [NoOp new];
}

- (AST *)statement {
    if (_currentToken->_type == TokenTypeBEGIN) {
        return [self compound_statement];
    } else if (_currentToken->_type == TokenTypeID) {
        return [self assignment_statement];
    }
    
    return [self empty];
    
}

- (NSArray *)statement_list {
    NSMutableArray *arr = [NSMutableArray array];
    
    AST *r = [self statement];
    [arr addObject:r];
    
    if (_currentToken->_type == TokenTypeSEMI) {
        [self eat:TokenTypeSEMI];
        [arr addObjectsFromArray:[self statement_list]];
    }
    
    return arr;
}

- (AST *)typeSpec {
    Type *t = [[Type alloc] initWithToken:_currentToken];
    [self eat:_currentToken->_type];
    return  t;
}

- (NSArray *)variableDeclaration {
    NSMutableArray *arr = [NSMutableArray array];
    [arr addObject:[[Var alloc] initWithToken:_currentToken]];
    [self eat:TokenTypeID];
    
    while (_currentToken->_type == TokenTypeCOMMA) {
        [self eat:TokenTypeCOMMA];
        [arr addObject:[[Var alloc] initWithToken:_currentToken]];
        [self eat:TokenTypeID];
    }
    [self eat:TokenTypeCOLON];
    
    AST *type = [self typeSpec];
    NSMutableArray *arr1 = [NSMutableArray array];
    [arr enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [arr1 addObject:[[VarDecl alloc] initWithType:type var:obj]];
    }];
    
    return arr1;
}

- (NSArray *)declarations {
    NSMutableArray *arr = [NSMutableArray array];
    if (_currentToken->_type == TokenTypeVAR) {
        [self eat:TokenTypeVAR];
        while (_currentToken->_type == TokenTypeID) {
            NSArray *vds = [self variableDeclaration];
            [arr addObjectsFromArray:vds];
            [self eat:TokenTypeSEMI];
        }
    }
    return arr;
}

- (AST *)block {
    return [[Block alloc] initWithDeclarations:[self declarations] compoundStatement:[self compound_statement]];
}

- (AST *)program {
    [self eat:TokenTypePROGRAM];
    Var *var = (Var *)[self variable];
    [self eat:TokenTypeSEMI];
    Program *p = [[Program alloc] initWithName:var->_token->_value block:[self block]];
    [self eat:TokenTypeDOT];
    return p;
}

- (AST *)compound_statement {
    [self eat:TokenTypeBEGIN];
    NSArray *nodes = [self statement_list];
    [self eat:TokenTypeEND];
    
    Compound *compound = [[Compound alloc] init];
    [compound->_children addObjectsFromArray:nodes];
    return compound;
}


- (AST *)factor {
    Token *t = _currentToken;
    
    if (t->_type == TokenTypeMINUS ||
        t->_type == TokenTypePlus) {
        [self eat:t->_type];
        return [[UnaryOp alloc] initWithToken:t right:[self factor]];
    } else if (t->_type == TokenTypeLP) {
        [self eat:TokenTypeLP];
        AST *r = [self expr];
        [self eat:TokenTypeRP];
        return r;
    } else if (t->_type == TokenTypeINTEGERCONST) {
        [self eat:TokenTypeINTEGERCONST];
        return [[Num alloc] initWithToken:t value:[t->_value integerValue]];
    } else if (t->_type == TokenTypeREALCONST) {
        [self eat:TokenTypeREALCONST];
        return [[Num alloc] initWithToken:t value:[t->_value floatValue]];
    } else {
        return [self variable];
    }
}

- (AST *)term {
    AST *r = [self factor];
    while (_currentToken->_type == TokenTypeMul ||
           _currentToken->_type == TokenTypeINTEGERDIV ||
           _currentToken->_type == TokenTypeFLOATDIV) {
        
        Token *t = _currentToken;
        
        [self eat:_currentToken->_type];
        r = [[BinOp alloc] initWithLeft:r right:[self factor] op:t];
    }
    
    return r;
}

- (AST *)expr {
    AST *r = [self term];
    while (_currentToken->_type == TokenTypeMINUS ||
           _currentToken->_type == TokenTypePlus) {
        
        Token *t = _currentToken;
        
        [self eat:_currentToken->_type];
        
        if (t->_type == TokenTypeMINUS) {
            r = [[BinOp alloc] initWithLeft:r right:[self term] op:t];
        } else {
            r = [[BinOp alloc] initWithLeft:r right:[self term] op:t];
        }
    }
    
    return r;
}

- (AST *)parse {
    AST *r = [self program];
    if (_currentToken->_type != TokenTypeEOF) {
        [NSException raise:@"invalid syntack" format:@""];
    }
    return r;
}
@end


@implementation Symbol
- (instancetype)initWithName:(NSString *)name type:(id)type {
    self = [super init];
    _name = name;
    _type = type;
    return self;
}
@end

@interface BuildInTypeSymbol : Symbol
- (instancetype)initWithName:(NSString *)name;
@end
@implementation BuildInTypeSymbol
- (instancetype)initWithName:(NSString *)name {
    self = [super init];
    _name = name;
    return self;
}
- (NSString *)description {
    return _name;
}
@end

@implementation VarSymbol
- (NSString *)description {
    return [NSString stringWithFormat:@"%@ : %@", _name, _type];
}
@end

@implementation SymbolTable
- (instancetype)init
{
    self = [super init];
    if (self) {
        _symbolTable = [NSMutableDictionary dictionary];
        [self define:[[BuildInTypeSymbol alloc] initWithName:@"INTEGER"]];
        [self define:[[BuildInTypeSymbol alloc] initWithName:@"REAL"]];
    }
    return self;
}
- (void)define:(Symbol *)s {
    _symbolTable[[s->_name lowercaseString]] = s;
}

- (Symbol *)lookup:(NSString *)n {
    return _symbolTable[[n lowercaseString]];
}

- (NSString *)description {
    NSMutableString *s = [NSMutableString string];
    [_symbolTable enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        [s appendFormat:@"%@\n", obj];
    }];
    return s;
}
@end

@interface Interpreter : NSObject {
    Parser *_parser;
}
- (instancetype)initWithParser:(Parser *)parser;
- (NSInteger)interpret;
@end

@implementation Interpreter
- (instancetype)initWithParser:(Parser *)parser {
    self = [super init];
    
    _parser = parser;
    
    return self;
}

- (NSInteger)interpret {
    return [[_parser parse] eval];
//    return [[_parser expr] eval];
}
@end

/*
 program ::= PROGRAM variable SEMI block DOT
 block  ::= declarations compound_statement
 declarations ::= VAR (variable_declaration SEMI)+ | empty
 variable_declaration ::= ID (COMMA ID)* COLON type_spec
 type_spec ::= INTEGER | REAL
 compound_statement ::= BEGIN statement_list END
 statement_list ::= statement | statement SEMI statement_list
 statement ::= compound_statement | assignment_statement | empty
 assignment_statement ::= variable ASSIGN expr
 empty ::=
 expr ::= term ((MINUS | PLUS) term)*
 term ::= factor ((MUL | INTEGER_DIV | FLOAT_DIV) factor)*
 factor ::= (MINUS | PLUS) factor | INTEGER_CONST | REAL_CONST | LP expr RP | variable
 variable ::= ID
 */

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        variablePool = [NSMutableDictionary dictionary];
        symTable = [SymbolTable new];
        
        
        
        Lexer *lexer = [[Lexer alloc] initWithText:
                        @" \
                        PROGRAM Part11; \
                        VAR \
                        number : INTEGER; \
                        a, b   : INTEGER; \
                        y      : REAL; \
                        \
                        BEGIN {Part11} \
                        number := 2; \
                        a := number ; \
                        b := 10 * a + 10 * number DIV 4; \
                        y := 20 / 7 + 3.14 \
                        END.  {Part11}"
                        ];
        Parser *parser = [[Parser alloc] initWithLexer:lexer];
        Interpreter *intepreter = [[Interpreter alloc] initWithParser:parser];
        NSLog(@"%ld", [intepreter interpret]);
        NSLog(@"%@", variablePool);
        NSLog(@"%@", symTable);
//        NSLog(@"%@", [parser expr]);
        // insert code here...
    }
    return 0;
}
// 如果使用 visit 方式，就可以把 symbolTable 的校验抽离出 interpreter
// 现在采用 AST 挂 eval 的方式，只能在 eval 里对 symbolTable 校验
