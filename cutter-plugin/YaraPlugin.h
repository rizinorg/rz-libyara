// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef YARA_PLUGIN_H
#define YARA_PLUGIN_H

#include <CutterPlugin.h>
#include <QLabel>
#include "YaraWidget.h"

class YaraPlugin : public QObject, CutterPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "re.rizin.cutter.plugins.CutterPlugin")
    Q_INTERFACES(CutterPlugin)

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;

    QString getName() const override { return "Yara Plugin"; }
    QString getAuthor() const override { return "deroad"; }
    QString getDescription() const override { return "Cutter YARA rules parser and generator."; }
    QString getVersion() const override { return "1.0"; }

    static void openHelpDialog();

private:
    void onActionAddYaraString();
    void onActionLoadYaraFile();
    void onActionLoadYaraFolder();

    YaraWidget *yaraDock;
    MainWindow *mainWindow;
};

#endif /* YARA_PLUGIN_H */
