// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef YARA_TEXT_EDITOR_H
#define YARA_TEXT_EDITOR_H

#include "ui_YaraTextEditor.h"

#include <QPlainTextEdit>
#include <QObject>
#include <QTimer>
#include <rz_yara.h>

class QPaintEvent;
class QResizeEvent;
class QSize;
class QWidget;
class YaraTextEditor;
class LineNumberArea;

namespace Ui {
class YaraTextEditor;
}

class YaraCompilerError
{
public:
    YaraCompilerError(bool isWarning, int line, QString message)
        : isWarning(isWarning), line(line), message(message)
    {
    }
    virtual ~YaraCompilerError() {}

    bool isWarning;
    int line;
    QString message;

private:
    YaraCompilerError() {}
};

class YaraTextEditor : public QPlainTextEdit
{
    Q_OBJECT

public:
    YaraTextEditor(QWidget *parent = nullptr);

    void lineNumberAreaPaintEvent(QPaintEvent *event);
    int lineNumberAreaWidth();

protected:
    void contextMenuEvent(QContextMenuEvent *event) override;
    bool event(QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private slots:
    void compileRuleAndCheckGrammar();
    void updateCompilerTimerEvent();
    void updateLineNumberAreaWidth(int newBlockCount);
    void highlightCurrentLine();
    void updateLineNumberArea(const QRect &rect, int dy);

private:
    void onActionSaveYaraRule();
    void onActionOpenHelp();
    static void handleCompileErrors(bool is_warning, const char *file, int line,
                                    const RzYaraRule *rule, const char *message, void *user_data);

    QList<YaraCompilerError> errors;
    QTimer *timer;
    QWidget *lineNumberArea;
    std::unique_ptr<Ui::YaraTextEditor> ui;
};

class LineNumberArea : public QWidget
{
public:
    LineNumberArea(YaraTextEditor *editor) : QWidget(editor), textEditor(editor) {}

    QSize sizeHint() const override { return QSize(textEditor->lineNumberAreaWidth(), 0); }

protected:
    void paintEvent(QPaintEvent *event) override { textEditor->lineNumberAreaPaintEvent(event); }

private:
    YaraTextEditor *textEditor;
};

#endif /* YARA_TEXT_EDITOR_H */
