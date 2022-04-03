// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "YaraWidget.h"

#include <core/MainWindow.h>
#include <common/Helpers.h>

#include <QTextCodec>
#include <QByteArray>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

YaraModel::YaraModel(QList<YaraDescription> *strings, QObject *parent)
    : QAbstractListModel(parent), strings(strings)
{
}

int YaraModel::rowCount(const QModelIndex &) const
{
    return strings->count();
}

int YaraModel::columnCount(const QModelIndex &) const
{
    return YaraModel::ColumnCount;
}

QVariant YaraModel::data(const QModelIndex &index, int role) const
{
    if (index.row() >= strings->count())
        return QVariant();

    const YaraDescription &desc = strings->at(index.row());

    switch (role) {
    case Qt::DisplayRole:
        switch (index.column()) {
        case OffsetColumn:
            return RzAddressString(desc.offset);
        case SizeColumn:
            return RzSizeString(desc.size);
        case NameColumn:
            return desc.name;
        default:
            return QVariant();
        }

    case YaraDescriptionRole:
        return QVariant::fromValue(desc);

    case Qt::ToolTipRole: {
        return desc.name;
    }

    default:
        return QVariant();
    }
}

QVariant YaraModel::headerData(int section, Qt::Orientation, int role) const
{
    switch (role) {
    case Qt::DisplayRole:
        switch (section) {
        case OffsetColumn:
            return tr("Offset");
        case SizeColumn:
            return tr("Size");
        case NameColumn:
            return tr("Name");
        default:
            return QVariant();
        }
    default:
        return QVariant();
    }
}

YaraProxyModel::YaraProxyModel(YaraModel *sourceModel, QObject *parent)
    : QSortFilterProxyModel(parent)
{
    setSourceModel(sourceModel);
}

bool YaraProxyModel::filterAcceptsRow(int row, const QModelIndex &parent) const
{
    QModelIndex index = sourceModel()->index(row, 0, parent);
    YaraDescription entry = index.data(YaraModel::YaraDescriptionRole).value<YaraDescription>();
    return qhelpers::filterStringContains(entry.name, this);
}

bool YaraProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    YaraDescription leftEntry = left.data(YaraModel::YaraDescriptionRole).value<YaraDescription>();
    YaraDescription rightEntry =
            right.data(YaraModel::YaraDescriptionRole).value<YaraDescription>();

    switch (left.column()) {
    case YaraModel::OffsetColumn:
        return leftEntry.offset < rightEntry.offset;
    case YaraModel::SizeColumn:
        return leftEntry.size < rightEntry.size;
    case YaraModel::NameColumn:
        return leftEntry.name < rightEntry.name;
    default:
        break;
    }

    return leftEntry.name < rightEntry.name;
}

MetadataModel::MetadataModel(QList<MetadataDescription> *metadata, QObject *parent)
    : QAbstractListModel(parent), metadata(metadata)
{
}

int MetadataModel::rowCount(const QModelIndex &) const
{
    return metadata->count();
}

int MetadataModel::columnCount(const QModelIndex &) const
{
    return MetadataModel::ColumnCount;
}

QVariant MetadataModel::data(const QModelIndex &index, int role) const
{
    if (index.row() >= metadata->count())
        return QVariant();

    const MetadataDescription &desc = metadata->at(index.row());

    switch (role) {
    case Qt::DisplayRole:
        switch (index.column()) {
        case ValueColumn:
            return desc.value;
        case NameColumn:
            return desc.name;
        default:
            return QVariant();
        }

    case MetadataDescriptionRole:
        return QVariant::fromValue(desc);

    case Qt::ToolTipRole: {
        return desc.name;
    }

    default:
        return QVariant();
    }
}

QVariant MetadataModel::headerData(int section, Qt::Orientation, int role) const
{
    switch (role) {
    case Qt::DisplayRole:
        switch (section) {
        case NameColumn:
            return tr("Name");
        case ValueColumn:
            return tr("Value");
        default:
            return QVariant();
        }
    default:
        return QVariant();
    }
}

MetadataProxyModel::MetadataProxyModel(MetadataModel *sourceModel, QObject *parent)
    : QSortFilterProxyModel(parent)
{
    setSourceModel(sourceModel);
}

bool MetadataProxyModel::filterAcceptsRow(int row, const QModelIndex &parent) const
{
    QModelIndex index = sourceModel()->index(row, 0, parent);
    MetadataDescription entry =
            index.data(MetadataModel::MetadataDescriptionRole).value<MetadataDescription>();
    return qhelpers::filterStringContains(entry.name, this);
}

bool MetadataProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    MetadataDescription leftEntry =
            left.data(MetadataModel::MetadataDescriptionRole).value<MetadataDescription>();
    MetadataDescription rightEntry =
            right.data(MetadataModel::MetadataDescriptionRole).value<MetadataDescription>();

    switch (left.column()) {
    case MetadataModel::NameColumn:
        return leftEntry.name < rightEntry.name;
    case MetadataModel::ValueColumn:
        return leftEntry.value < rightEntry.value;
    default:
        break;
    }

    return leftEntry.name < rightEntry.name;
}

YaraWidget::YaraWidget(MainWindow *main)
    : CutterDockWidget(main), ui(new Ui::YaraWidget), blockMenu(new YaraViewMenu(this, mainWindow))
{
    ui->setupUi(this);

    matchesModel = new YaraModel(&matches, this);
    matchesProxyModel = new YaraProxyModel(matchesModel, this);
    ui->yaraMatchView->setModel(matchesProxyModel);
    ui->yaraMatchView->sortByColumn(YaraModel::OffsetColumn, Qt::AscendingOrder);
    ui->yaraMatchView->resizeColumnToContents(0);
    ui->yaraMatchView->resizeColumnToContents(1);
    qhelpers::setVerticalScrollMode(ui->yaraMatchView);

    this->connect(ui->yaraMatchView->selectionModel(), &QItemSelectionModel::currentChanged, this,
                  &YaraWidget::onSelectedItemChanged);

    stringsModel = new YaraModel(&strings, this);
    stringsProxyModel = new YaraProxyModel(stringsModel, this);
    ui->yaraStringsView->setModel(stringsProxyModel);
    ui->yaraStringsView->sortByColumn(YaraModel::OffsetColumn, Qt::AscendingOrder);
    ui->yaraStringsView->resizeColumnToContents(0);
    ui->yaraStringsView->resizeColumnToContents(1);
    ui->yaraStringsView->resizeColumnToContents(2);
    qhelpers::setVerticalScrollMode(ui->yaraStringsView);

    this->connect(ui->yaraStringsView->selectionModel(), &QItemSelectionModel::currentChanged, this,
                  &YaraWidget::onSelectedItemChanged);

    metaModel = new MetadataModel(&metadata, this);
    metaProxyModel = new MetadataProxyModel(metaModel, this);
    ui->yaraMetadataView->setModel(metaProxyModel);
    ui->yaraMetadataView->resizeColumnToContents(0);
    ui->yaraMetadataView->resizeColumnToContents(1);
    ui->yaraMetadataView->resizeColumnToContents(2);
    qhelpers::setVerticalScrollMode(ui->yaraMetadataView);

    this->connect(ui->yaraStringsView->selectionModel(), &QItemSelectionModel::currentChanged, this,
                  &YaraWidget::onSelectedItemChanged);

    ui->yaraRuleEditor->setTabStopDistance(40);
    this->syntax.reset(new YaraSyntax(ui->yaraRuleEditor->document()));

    ui->yaraTabWidget->setCurrentIndex(StringsMode);

    this->connect(this, &QWidget::customContextMenuRequested, this,
                  &YaraWidget::showItemContextMenu);
    this->setContextMenuPolicy(Qt::CustomContextMenu);

    this->connect(Core(), &CutterCore::refreshAll, this, &YaraWidget::reloadWidget);
    this->connect(Core(), &CutterCore::flagsChanged, this, &YaraWidget::reloadWidget);

    this->addActions(this->blockMenu->actions());
}

void YaraWidget::reloadWidget()
{
    refreshStrings();
    refreshMatches();
    refreshRule();
    refreshMetadata();
}

static inline QList<YaraDescription> toYaraDescriptionList(QJsonArray &array)
{
    QList<YaraDescription> list;

    for (const QJsonValue &value : array) {
        YaraDescription desc;
        QJsonObject obj = value.toObject();

        desc.offset = obj["offset"].toVariant().toULongLong();
        desc.size = obj["size"].toVariant().toULongLong();
        desc.name = obj["name"].toString();

        list << desc;
    }

    return list;
}

static QJsonArray toJsonArray(QString &string)
{
    QTextCodec *codec = QTextCodec::codecForName("UTF-8");
    QByteArray doc = codec->fromUnicode(string);
    QJsonDocument jdoc = QJsonDocument::fromJson(doc);
    return jdoc.array();
}

static QJsonObject toJsonObject(QString &string)
{
    QTextCodec *codec = QTextCodec::codecForName("UTF-8");
    QByteArray doc = codec->fromUnicode(string);
    QJsonDocument jdoc = QJsonDocument::fromJson(doc);
    return jdoc.object();
}

void YaraWidget::refreshStrings()
{
    stringsModel->beginResetModel();
    QString res = Core()->cmd("yarasj");
    QJsonArray array = toJsonArray(res);
    strings = toYaraDescriptionList(array);
    stringsModel->endResetModel();
}

void YaraWidget::refreshMatches()
{
    matchesModel->beginResetModel();
    QString res = Core()->cmd("yaraMj");
    QJsonArray array = toJsonArray(res);
    matches = toYaraDescriptionList(array);
    matchesModel->endResetModel();
}

void YaraWidget::refreshRule()
{
    QString rule = Core()->cmd("yarac placeholder_name");
    ui->yaraRuleEditor->setPlainText(rule);
    syntax->rehighlight();
}

void YaraWidget::refreshMetadata()
{
    metaModel->beginResetModel();
    metadata.clear();
    QString res = Core()->cmd("yaramj");
    QJsonObject json = toJsonObject(res);

    foreach (const QString &key, json.keys()) {
        MetadataDescription desc;
        desc.name = key;
        if (YaraAddMetaDialog::isKeyword(key)) {
            desc.value = tr("Autofill");
        } else if (json[key].isBool()) {
            desc.value = json[key].toBool() ? "true" : "false";
        } else if (json[key].isDouble()) {
            double dbl = json[key].toDouble();
            desc.value = QString::number(dbl);
        } else {
            desc.value = json[key].toString();
        }
        metadata << desc;
    }
    metaModel->endResetModel();
}

void YaraWidget::switchToMatches()
{
    ui->yaraTabWidget->setCurrentIndex(MatchesMode);
}

void YaraWidget::onSelectedItemChanged(const QModelIndex &index)
{
    int mode = ui->yaraTabWidget->currentIndex();
    if (!index.isValid()) {
        blockMenu->clearTarget();
        if (mode == YaraViewMode::MetadataMode) {
            MetadataDescription entry;
            blockMenu->setMetaTarget(entry);
        } else {
            YaraDescription entry;
            blockMenu->setYaraTarget(entry, mode == YaraViewMode::StringsMode);
        }
        return;
    }

    switch (mode) {
    case YaraViewMode::StringsMode: {
        const YaraDescription &sentry = strings.at(index.row());
        blockMenu->setYaraTarget(sentry, true);
    } break;
    case YaraViewMode::MatchesMode: {
        const YaraDescription &mentry = matches.at(index.row());
        blockMenu->setYaraTarget(mentry, false);
    } break;
    case YaraViewMode::RuleMode:
        break;
    case YaraViewMode::MetadataMode: {
        const MetadataDescription &dentry = metadata.at(index.row());
        blockMenu->setMetaTarget(dentry);
    } break;
    }
}

void YaraWidget::showItemContextMenu(const QPoint &pt)
{
    QModelIndex position;
    int index = ui->yaraTabWidget->currentIndex();
    switch (index) {
    case YaraViewMode::StringsMode:
        position = ui->yaraStringsView->currentIndex();
        if (position.isValid()) {
            const YaraDescription &entry = strings.at(position.row());
            blockMenu->setYaraTarget(entry, true);
        } else {
            YaraDescription entry;
            blockMenu->setYaraTarget(entry, true);
        }
        blockMenu->exec(this->mapToGlobal(pt));
    case YaraViewMode::MatchesMode:
        position = ui->yaraMatchView->currentIndex();
        if (position.isValid()) {
            const YaraDescription &entry = matches.at(position.row());
            blockMenu->setYaraTarget(entry, false);
        } else {
            YaraDescription entry;
            blockMenu->setYaraTarget(entry, false);
        }
        blockMenu->exec(this->mapToGlobal(pt));
        break;
    case YaraViewMode::RuleMode:
        break;
    case YaraViewMode::MetadataMode:
        position = ui->yaraMetadataView->currentIndex();
        if (position.isValid()) {
            const MetadataDescription &entry = metadata.at(position.row());
            blockMenu->setMetaTarget(entry);
        } else {
            MetadataDescription entry;
            blockMenu->setMetaTarget(entry);
        }
        blockMenu->exec(this->mapToGlobal(pt));
        break;
    default:
        break;
    }
}