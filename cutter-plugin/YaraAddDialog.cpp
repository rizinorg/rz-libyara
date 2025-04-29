// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "YaraAddDialog.h"
#include "ui_YaraAddDialog.h"

#include <QIntValidator>
#include <QRegularExpressionValidator>
#include "core/Cutter.h"

YaraAddDialog::YaraAddDialog(RVA offset, QWidget *parent)
    : QDialog(parent), ui(new Ui::YaraAddDialog), flagOffset(offset)
{
    // Setup UI
    ui->setupUi(this);
    setWindowFlags(windowFlags() & (~Qt::WindowContextHelpButtonHint));

    ui->sizeEdit->setText("1");
    ui->nameEdit->setText("placeholder");

    RzCoreLocked core(Core());
    RzFlagItem *flag = rz_flag_get_i(core->flags, offset);
    if (flag) {
        QString name = QString(flag->name);
        if (name.startsWith("str.")) {
            name = name.replace("str.", "");
            name = name.replace(QRegularExpression("[^A-Za-z0-9_]+"), "");
            if (!name.isEmpty()) {
                ui->nameEdit->setText(name);
            }
            ui->sizeEdit->setText(QString::number(flag->size > 0 ? flag->size : 1));
        }
    }

    QRegularExpression rx("[A-Za-z0-9_]+");
    auto nameValidator = new QRegularExpressionValidator(rx, this);
    ui->nameEdit->setValidator(nameValidator);

    auto size_validator = new QIntValidator(ui->sizeEdit);
    size_validator->setBottom(1);
    ui->sizeEdit->setValidator(size_validator);

    ui->labelAction->setText(tr("Add Yara string at %1").arg(RzAddressString(flagOffset)));

    ui->typeSelector->addItem(tr("String"), "yarasas");
    ui->typeSelector->addItem(tr("Bytes"), "yarasab");
    ui->typeSelector->addItem(tr("Assembly (masked)"), "yarasam");
    ui->typeSelector->addItem(tr("Assembly (raw)"), "yarasau");
    ui->typeSelector->setCurrentIndex(0);

    // Connect slots
    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &YaraAddDialog::buttonBoxAccepted);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &YaraAddDialog::buttonBoxRejected);
}

YaraAddDialog::~YaraAddDialog() {}

void YaraAddDialog::buttonBoxAccepted()
{
    RVA size = ui->sizeEdit->text().toULongLong();
    QString name = ui->nameEdit->text();
    QString command = ui->typeSelector->currentData().toString();

    if (!name.isEmpty() && size > 0) {
        Core()->cmd(command + " " + name + " " + RzSizeString(size) + " @ "
                    + RzAddressString(flagOffset));
    }
    close();
    this->setResult(QDialog::Accepted);
}

void YaraAddDialog::buttonBoxRejected()
{
    close();
    this->setResult(QDialog::Rejected);
}
