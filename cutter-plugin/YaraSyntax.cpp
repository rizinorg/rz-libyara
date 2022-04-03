// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "YaraSyntax.h"
#include <common/Configuration.h>

#define Config() (Configuration::instance())
#define ConfigColor(x) Config()->getColor(x)

YaraSyntax::YaraSyntax(QTextDocument *parent)
    : QSyntaxHighlighter(parent), commentStartExpression("/\\*"), commentEndExpression("\\*/")
{
    HighlightingRule rule;

    // yara keywords names (first to be done.)
    rule.pattern.setPattern(
            "\\b(all|and|any|ascii|at|contains|entrypoint|false|filesize|fullword|for|"
            "global|in|import|include|int8|int16|int32|int8be|int16be|int32be|matches|nocase|"
            "not|or|of|private|them|true|uint8|uint16|uint32|uint8be|uint16be|"
            "uint32be|wide|xor)\\b");
    rule.format.clearBackground();
    rule.format.clearForeground();
    rule.format.setFontWeight(QFont::Normal);
    rule.format.setForeground(ConfigColor("flow"));
    highlightingRules.append(rule);

    // yara special keyword
    rule.pattern.setPattern("\\b(rule|meta|strings|condition)\\b");
    rule.format.clearBackground();
    rule.format.clearForeground();
    rule.format.setFontWeight(QFont::Bold);
    rule.format.setForeground(ConfigColor("call"));
    highlightingRules.append(rule);

    // yara values names
    rule.pattern.setPattern("\\$\\b[A-Za-z]([A-Za-z0-9_]+)?\\b");
    rule.format.clearBackground();
    rule.format.clearForeground();
    rule.format.setFontWeight(QFont::Normal);
    rule.format.setForeground(ConfigColor("fname"));
    highlightingRules.append(rule);

    // bytes
    rule.pattern.setPattern(
            "(\\b[A-Fa-f0-9][A-Fa-f0-9]\\b|\\ \\?[A-Fa-f0-9]\\b|\\b[A-Fa-f0-9]\\?\\ |\\?\\?\\ )");
    rule.format.clearBackground();
    rule.format.clearForeground();
    rule.format.setFontWeight(QFont::Normal);
    rule.format.setFontItalic(false);
    rule.format.setForeground(ConfigColor("graph.ujump"));
    highlightingRules.append(rule);

    // number/float
    rule.pattern.setPattern("\\b\\d+(\\.\\d+)?$");
    rule.format.clearBackground();
    rule.format.clearForeground();
    rule.format.setFontWeight(QFont::Normal);
    rule.format.setForeground(ConfigColor("graph.ujump"));
    highlightingRules.append(rule);

    // single-line comment
    rule.pattern.setPattern("//[^\n]*");
    rule.format.clearBackground();
    rule.format.clearForeground();
    rule.format.setFontWeight(QFont::Normal);
    rule.format.setFontItalic(false);
    rule.format.setForeground(ConfigColor("comment"));
    highlightingRules.append(rule);

    // quotation
    rule.pattern.setPattern("\".*\"");
    rule.format.clearBackground();
    rule.format.clearForeground();
    rule.format.setFontWeight(QFont::Normal);
    rule.format.setFontItalic(false);
    rule.format.setForeground(ConfigColor("gui.cflow"));
    highlightingRules.append(rule);

    multiLineCommentFormat.setForeground(ConfigColor("comment"));
}

void YaraSyntax::highlightBlock(const QString &text)
{
    for (const auto &it : highlightingRules) {
        auto matchIterator = it.pattern.globalMatch(text);
        while (matchIterator.hasNext()) {
            const auto match = matchIterator.next();
            setFormat(match.capturedStart(), match.capturedLength(), it.format);
        }
    }

    setCurrentBlockState(0);

    int startIndex = 0;
    if (previousBlockState() != 1) {
        startIndex = text.indexOf(commentStartExpression);
    }

    while (startIndex >= 0) {
        const auto match = commentEndExpression.match(text, startIndex);
        const int endIndex = match.capturedStart();
        int commentLength = 0;

        if (endIndex == -1) {
            setCurrentBlockState(1);
            commentLength = text.length() - startIndex;
        } else {
            commentLength = endIndex - startIndex + match.capturedLength();
        }

        setFormat(startIndex, commentLength, multiLineCommentFormat);
        startIndex = text.indexOf(commentStartExpression, startIndex + commentLength);
    }
}
