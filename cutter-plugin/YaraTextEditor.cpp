// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "YaraTextEditor.h"

#include <QScrollBar>
#include <QTextBlock>
#include <QPainter>
#include <QToolTip>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>

#include <cmath>
#include <common/Configuration.h>

#define Config() (Configuration::instance())
#define ConfigColor(x) Config()->getColor(x)

YaraTextEditor::YaraTextEditor(QWidget *parent) : QPlainTextEdit(parent), ui(new Ui::YaraTextEditor)
{
    ui->setupUi(this);
    timer = new QTimer(this);
    lineNumberArea = new LineNumberArea(this);

    connect(this, &YaraTextEditor::blockCountChanged, this,
            &YaraTextEditor::updateLineNumberAreaWidth);
    connect(this, &YaraTextEditor::textChanged, this, &YaraTextEditor::updateCompilerTimerEvent);
    connect(this, &YaraTextEditor::updateRequest, this, &YaraTextEditor::updateLineNumberArea);
    connect(this, &YaraTextEditor::cursorPositionChanged, this,
            &YaraTextEditor::highlightCurrentLine);
    connect(timer, &QTimer::timeout, this, &YaraTextEditor::compileRuleAndCheckGrammar);

    updateLineNumberAreaWidth(0);
    highlightCurrentLine();
    setMouseTracking(true);
}

void YaraTextEditor::contextMenuEvent(QContextMenuEvent *event)
{
    QMenu *menu = createStandardContextMenu();
    QAction *actionSaveYaraRule = menu->addAction(tr("Save Yara Rule to File"));
    connect(actionSaveYaraRule, &QAction::triggered, this, &YaraTextEditor::onActionSaveYaraRule);
    menu->insertSeparator(actionSaveYaraRule);
    menu->exec(event->globalPos());
    delete menu;
}

void YaraTextEditor::onActionSaveYaraRule()
{
    QString errorLine;
    for (auto error : errors) {
        if (!error.isWarning) {
            errorLine += QString("\nline %1: %2").arg(error.line + 1).arg(error.message);
        }
    }
    if (!errorLine.isEmpty()) {
        QMessageBox::critical(nullptr, tr("Invalid Yara Rule"),
                              tr("This Yara Rule failed to compile, therefore cannot be saved.\n%1")
                                      .arg(errorLine));
        return;
    }

    QString yarafile = QFileDialog::getSaveFileName(this, tr("Save Yara Rule"), "untitled.yara",
                                                    tr("Yara Rule (*.yara)"));
    if (yarafile.isEmpty()) {
        return;
    }
    QFile data(yarafile);
    if (data.open(QFile::WriteOnly | QFile::Truncate)) {
        QTextStream out(&data);
        out << toPlainText();
    }
}

void YaraTextEditor::handleCompileErrors(bool is_warning, const char *file, int line,
                                         const RzYaraRule *rule, const char *message,
                                         void *user_data)
{
    YaraTextEditor *editor = static_cast<YaraTextEditor *>(user_data);
    YaraCompilerError error(is_warning, line - 1, message);
    editor->errors << error;
}

void YaraTextEditor::compileRuleAndCheckGrammar()
{
    timer->stop();
    errors.clear();
    QString toCompile = toPlainText();
    if (toCompile.isEmpty()) {
        return;
    }

    RzYaraCompiler *comp = rz_yara_compiler_new((RzYaraCompilerErrorCb)&handleCompileErrors, this);
    if (!comp) {
        return;
    }

    const char *string = toCompile.toLatin1().constData();
    rz_yara_compiler_parse_string(comp, string);
    rz_yara_compiler_free(comp);

    emit highlightCurrentLine();
}

void YaraTextEditor::updateCompilerTimerEvent()
{
    errors.clear();
    // 1500 ms is 1.5 secs
    if (!timer->isActive()) {
        timer->start(1500);
    } else {
        timer->stop();
        timer->start(1500);
    }
    emit highlightCurrentLine();
}

int YaraTextEditor::lineNumberAreaWidth()
{
    int max = qMax(1, blockCount());
    int digits = log10(max) + 1;
    return 25 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * digits;
}

void YaraTextEditor::updateLineNumberArea(const QRect &rect, int dy)
{
    if (dy) {
        lineNumberArea->scroll(0, dy);
    } else {
        lineNumberArea->update(0, rect.y(), lineNumberArea->width(), rect.height());
    }

    if (rect.contains(viewport()->rect())) {
        updateLineNumberAreaWidth(0);
    }
}

void YaraTextEditor::updateLineNumberAreaWidth(int newBlockCount)
{
    (void)newBlockCount;
    setViewportMargins(lineNumberAreaWidth(), 0, 10, 0);
}

void YaraTextEditor::resizeEvent(QResizeEvent *e)
{
    QPlainTextEdit::resizeEvent(e);

    QRect cr = contentsRect();
    lineNumberArea->setGeometry(QRect(cr.left(), cr.top(), lineNumberAreaWidth(), cr.height()));
}

bool YaraTextEditor::event(QEvent *event)
{
    if (event->type() == QEvent::ToolTip) {
        QString message;
        QHelpEvent *helpEvent = static_cast<QHelpEvent *>(event);
        QTextCursor cursor = cursorForPosition(helpEvent->pos());

        int line = cursor.blockNumber();
        for (auto error : errors) {
            if (line == error.line) {
                message = QString("Yara: %1: %2")
                                  .arg(error.isWarning ? "warning" : "error")
                                  .arg(error.message);
                break;
            }
        }

        if (message.isEmpty()) {
            QToolTip::hideText();
        } else {
            QToolTip::showText(helpEvent->globalPos(), message);
        }
        return true;
    }
    return QPlainTextEdit::event(event);
}

void YaraTextEditor::highlightCurrentLine()
{
    QList<QTextEdit::ExtraSelection> extraSelections;
    bool isDark = Config()->windowColorIsDark();
    QColor warningLine = isDark ? QColor(107, 68, 0) : QColor(255, 238, 125);
    QColor errorLine = isDark ? QColor(107, 0, 0) : QColor(255, 134, 125);

    for (auto error : errors) {
        QTextEdit::ExtraSelection selection;
        QTextCursor cursor(document()->findBlockByLineNumber(error.line));
        QColor lineHighlight = error.isWarning ? warningLine : errorLine;

        selection.format.setBackground(lineHighlight);
        selection.format.setProperty(QTextFormat::FullWidthSelection, true);
        selection.cursor = cursor;
        selection.cursor.clearSelection();
        extraSelections << selection;
    }

    if (!isReadOnly()) {
        QTextEdit::ExtraSelection selection;
        QColor lineHighlight = ConfigColor("lineHighlight");

        selection.format.setBackground(lineHighlight);
        selection.format.setProperty(QTextFormat::FullWidthSelection, true);
        selection.cursor = textCursor();
        selection.cursor.clearSelection();
        extraSelections << selection;
    }

    setExtraSelections(extraSelections);
}

void YaraTextEditor::lineNumberAreaPaintEvent(QPaintEvent *event)
{
    QPainter painter(lineNumberArea);
    QColor text = ConfigColor("text");
    QTextBlock block = firstVisibleBlock();
    int blockNumber = block.blockNumber();
    int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
    int bottom = top + qRound(blockBoundingRect(block).height());

    while (block.isValid() && top <= event->rect().bottom()) {
        if (block.isVisible() && bottom >= event->rect().top()) {
            QString number = QString::number(blockNumber + 1) + "  ";
            painter.setPen(text);
            painter.drawText(0, top, lineNumberArea->width(), fontMetrics().height(),
                             Qt::AlignRight, number);
        }

        block = block.next();
        top = bottom;
        bottom = top + qRound(blockBoundingRect(block).height());
        ++blockNumber;
    }
}
