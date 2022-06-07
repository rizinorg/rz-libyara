#include <QLabel>
#include <QHBoxLayout>
#include <QPushButton>
#include <QAction>
#include <QFile>
#include <QFileDialog>
#include <QMenuBar>

#include "YaraPlugin.h"
#include "YaraAddDialog.h"

#include <common/TempConfig.h>
// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <common/Configuration.h>
#include <MainWindow.h>

void YaraPlugin::setupPlugin() {}

void YaraPlugin::setupInterface(MainWindow *main)
{
    mainWindow = main;
    yaraDock = new YaraWidget(main);
    main->addPluginDockWidget(yaraDock);

    QMenu *menuFile = main->getMenuByType(MainWindow::MenuType::File);
    QMenu *menu = new QMenu(tr("Apply Yara Rules..."));
    auto entry = menuFile->addMenu(menu);
    menuFile->insertSeparator(entry);

    QAction *actionLoadYaraFile = menu->addAction(tr("Apply Yara Rule From File"));
    QAction *actionLoadYaraFolder = menu->addAction(tr("Apply All Yara Rules In Directory"));
    connect(actionLoadYaraFile, &QAction::triggered, this, &YaraPlugin::onActionLoadYaraFile);
    connect(actionLoadYaraFolder, &QAction::triggered, this, &YaraPlugin::onActionLoadYaraFolder);

    menu = main->getContextMenuExtensions(MainWindow::ContextMenuType::Disassembly);
    QAction *actionAddYaraString = menu->addAction(tr("Add Yara String"));
    connect(actionAddYaraString, &QAction::triggered, this, &YaraPlugin::onActionAddYaraString);

    // Currently is not possible to get the correct address from an "Addressable" ContextMenuType
    // menu = main->getContextMenuExtensions(MainWindow::ContextMenuType::Addressable);
    // actionAddYaraString = menu->addAction(tr("Add Yara String"));
    // connect(actionAddYaraString, &QAction::triggered, this, &YaraPlugin::onActionAddYaraString);
}

void YaraPlugin::onActionAddYaraString()
{
    YaraAddDialog dialog(Core()->getOffset());
    if (dialog.exec()) {
        emit Core()->refreshCodeViews();
        emit Core()->flagsChanged();
    }
}

void YaraPlugin::onActionLoadYaraFile()
{
    QFileDialog dialog(mainWindow);
    dialog.setWindowTitle(tr("Apply Yara Rule From File"));

    if (!dialog.exec()) {
        return;
    }

    const QString &yarafile = QDir::toNativeSeparators(dialog.selectedFiles().first());
    if (!yarafile.isEmpty()) {
        Core()->cmd("yaral '" + yarafile + "'");
        yaraDock->switchToMatches();
        emit Core()->flagsChanged();
    }
}

void YaraPlugin::onActionLoadYaraFolder()
{
    QString yaradir = QFileDialog::getExistingDirectory(mainWindow, tr("Open Directory"), "",
                                                        QFileDialog::ShowDirsOnly
                                                                | QFileDialog::DontResolveSymlinks);
    if (!yaradir.isEmpty()) {
        Core()->cmd("yarad '" + yaradir + "'");
        yaraDock->switchToMatches();
        emit Core()->flagsChanged();
    }
}

void YaraPlugin::openHelpDialog()
{
    auto description =
            tr("Hello, Welcome to Yara Help\n\n"
               "How to use one or multiple Yara rules:\n"
               " - Top Menu > File > Apply Yara Rule... > Apply Yara Rule From File\n"
               " - Top Menu > File > Apply Yara Rule... > Apply All Yara Rules In Directory\n\n"
               "How to see matches from loaded rules:\n"
               " 1. Open the 'Yara' view\n"
               " 2. Select the 'Matches' Tab\n"
               " 3. Double click to seek at the matched location.\n"
               "Some locations might not be visible due the match being outside the virtual "
               "address space.\n\n"
               "How to create a rule:\n"
               " 1. Open the 'Disassembly' view.\n"
               " 2. Left click on the Disassembly view.\n"
               " 3. Menu > Plugins > Add Yara String.\n"
               " 4. Select the type, give it a name and set the size (in bytes).\n"
               " 5. Open the 'Yara' view and go to the Rule Tab.\n\n"
               "How to add metadata to the rule:\n"
               " 1. Open the 'Yara' view and go to the Metadata Tab.\n"
               " 2. Left click > Add New Entry.\n"
               " 3. Each entry is made of a keyword and value, but some can be automatically "
               "filled.\n");
    QMessageBox::information(nullptr, tr("Yara Help"), description);
}