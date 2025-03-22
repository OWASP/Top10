import type { ASTNodeTypes } from "./ASTNodeTypes";
import type {
    AnyTxtNode,
    TxtBlockQuoteNode,
    TxtBreakNode,
    TxtCodeBlockNode,
    TxtCommentNode,
    TxtDeleteNode,
    TxtDocumentNode,
    TxtEmphasisNode,
    TxtHeaderNode,
    TxtHorizontalRuleNode,
    TxtHtmlNode,
    TxtImageNode,
    TxtCodeNode,
    TxtLinkNode,
    TxtListItemNode,
    TxtListNode,
    TxtParagraphNode,
    TxtStrNode,
    TxtStrongNode,
    TxtTableCellNode,
    TxtTableNode,
    TxtTableRowNode
} from "./NodeType";

/**
 * Type utility for TxtNodeType
 * Return TxtNode interface for the TxtNodeTYpe
 *
 * @example
 * ```ts
 * type NodeType = TxtNodeTypeOfNode<ASTNodeTypes.Document>;
 * ```
 */
export type TypeofTxtNode<T extends ASTNodeTypes | string> =
    // Root
    T extends ASTNodeTypes.Document
        ? TxtDocumentNode
        : T extends ASTNodeTypes.DocumentExit
        ? TxtDocumentNode
        : T extends ASTNodeTypes.Paragraph // Paragraph Str.
        ? TxtParagraphNode
        : T extends ASTNodeTypes.ParagraphExit
        ? TxtParagraphNode
        : T extends ASTNodeTypes.BlockQuote // > Str
        ? TxtBlockQuoteNode
        : T extends ASTNodeTypes.BlockQuoteExit
        ? TxtBlockQuoteNode
        : T extends ASTNodeTypes.List // - item
        ? TxtListNode
        : T extends ASTNodeTypes.ListExit
        ? TxtListNode
        : T extends ASTNodeTypes.ListItem // - item
        ? TxtListItemNode
        : T extends ASTNodeTypes.ListItemExit
        ? TxtListItemNode
        : T extends ASTNodeTypes.Header // # Str
        ? TxtHeaderNode
        : T extends ASTNodeTypes.HeaderExit
        ? TxtHeaderNode
        : T extends ASTNodeTypes.CodeBlock
        ? /* ```
           * code block
           * ```
           */
          TxtCodeBlockNode
        : T extends ASTNodeTypes.CodeBlockExit
        ? TxtCodeBlockNode
        : T extends ASTNodeTypes.HtmlBlock // <div>\n</div>
        ? TxtHtmlNode
        : T extends ASTNodeTypes.HtmlBlockExit
        ? TxtHtmlNode
        : T extends ASTNodeTypes.Link // [link](https://example.com)
        ? TxtLinkNode
        : T extends ASTNodeTypes.LinkExit
        ? TxtLinkNode
        : T extends ASTNodeTypes.Delete // ~~Str~~
        ? TxtDeleteNode
        : T extends ASTNodeTypes.DeleteExit
        ? TxtDeleteNode
        : T extends ASTNodeTypes.Emphasis // *Str*
        ? TxtEmphasisNode
        : T extends ASTNodeTypes.EmphasisExit
        ? TxtEmphasisNode
        : T extends ASTNodeTypes.Strong // __Str__
        ? TxtStrongNode
        : T extends ASTNodeTypes.StrongExit
        ? TxtStrongNode
        : T extends ASTNodeTypes.Break // Str<space><space>
        ? TxtBreakNode
        : T extends ASTNodeTypes.BreakExit
        ? TxtBreakNode
        : T extends ASTNodeTypes.Image // ![alt](https://example.com/img)
        ? TxtImageNode
        : T extends ASTNodeTypes.ImageExit
        ? TxtImageNode
        : T extends ASTNodeTypes.HorizontalRule // ----
        ? TxtHorizontalRuleNode
        : T extends ASTNodeTypes.HorizontalRuleExit
        ? TxtHorizontalRuleNode
        : T extends ASTNodeTypes.Comment // Markdown does not have comment(It is Html comment). Some plugins use comment as a marker.
        ? TxtCommentNode
        : T extends ASTNodeTypes.CommentExit
        ? TxtCommentNode
        : T extends ASTNodeTypes.Str // Str
        ? TxtStrNode
        : T extends ASTNodeTypes.StrExit
        ? TxtStrNode
        : T extends ASTNodeTypes.Code // `code`
        ? TxtCodeNode
        : T extends ASTNodeTypes.CodeExit
        ? TxtCodeNode
        : T extends ASTNodeTypes.Html // <span>Str</span>
        ? TxtHtmlNode
        : T extends ASTNodeTypes.HtmlExit
        ? TxtHtmlNode
        : T extends ASTNodeTypes.Table
        ? TxtTableNode
        : T extends ASTNodeTypes.TableExit
        ? TxtTableNode
        : T extends ASTNodeTypes.TableRow
        ? TxtTableRowNode
        : T extends ASTNodeTypes.TableRowExit
        ? TxtTableRowNode
        : T extends ASTNodeTypes.TableCell
        ? TxtTableCellNode
        : T extends ASTNodeTypes.TableCellExit
        ? TxtTableCellNode
        : AnyTxtNode;
