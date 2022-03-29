// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef YARA_SYNTAX_H
#define YARA_SYNTAX_H

#include "CutterCommon.h"
#include <QSyntaxHighlighter>
#include <QVector>
#include <QTextDocument>
#include <QRegularExpression>
#include <QTextCharFormat>

class YaraSyntax : public QSyntaxHighlighter
{
    Q_OBJECT

public:
    YaraSyntax(QTextDocument *parent = nullptr);
    virtual ~YaraSyntax() = default;

protected:
    void highlightBlock(const QString &text) override;

private:
    struct HighlightingRule
    {
        QRegularExpression pattern;
        QTextCharFormat format;
    };

    QVector<HighlightingRule> highlightingRules;

    QRegularExpression commentStartExpression;
    QRegularExpression commentEndExpression;

    QTextCharFormat multiLineCommentFormat;
};

#endif // YARA_SYNTAX_H
