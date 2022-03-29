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
#include <common/Configuration.h>
#include <MainWindow.h>

void YaraPlugin::setupPlugin() {}

void YaraPlugin::setupInterface(MainWindow *main)
{
    mainWindow = main;
    yaraDock = new YaraWidget(main);
    main->addPluginDockWidget(yaraDock);

    //QMenuBar *menuBar = qobject_cast<QMenuBar*>(main->getMenuByType(MainWindow::MenuType::File)->parent());
    //QMenu *menu = menuBar->addMenu(tr("Yara"));
    QMenu *menuFile = main->getMenuByType(MainWindow::MenuType::File);

    auto entry = menuFile->actions().at(5);
    QMenu *menu = new QMenu(tr("Yara"));
    entry = menuFile->insertMenu(entry, menu);
    menuFile->insertSeparator(entry);

    QAction *actionLoadYaraFile = menu->addAction(tr("Apply Yara Rule From File"));
    QAction *actionLoadYaraFolder = menu->addAction(tr("Apply All Yara Rules In Directory"));
    connect(actionLoadYaraFile, &QAction::triggered, this, &YaraPlugin::onActionLoadYaraFile);
    connect(actionLoadYaraFolder, &QAction::triggered, this, &YaraPlugin::onActionLoadYaraFolder);

    QMenu *disassemblyContextMenu = main->getContextMenuExtensions(MainWindow::ContextMenuType::Disassembly);
    actionAddYaraString = disassemblyContextMenu->addAction(tr("Add Yara String"));
    connect(actionAddYaraString, &QAction::triggered, this, &YaraPlugin::onActionAddYaraString);
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
    dialog.setWindowTitle(tr("Load Yara Rule From File"));

    if (!dialog.exec()) {
        return;
    }

    const QString &yarafile = QDir::toNativeSeparators(dialog.selectedFiles().first());
    if (!yarafile.isEmpty()) {
        Core()->cmd("yaral " + yarafile);
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
        Core()->cmd("yarad " + yaradir);
        yaraDock->switchToMatches();
        emit Core()->flagsChanged();
    }
}