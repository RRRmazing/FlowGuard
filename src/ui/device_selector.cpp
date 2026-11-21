// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "ui/device_selector.h"
#include <QAbstractItemView>
#include <QApplication>
#include <QPainter>
#include <QScreen>
#include <QStringList>
#include <QStyleOptionViewItem>
#include <QStyledItemDelegate>
#include <algorithm>

namespace flowguard
{
namespace
{
QString key(QString id)
{
    const int begin = id.indexOf('{'), end = id.indexOf('}');
    if (begin >= 0 && end > begin)
        id = id.mid(begin + 1, end - begin - 1);
    return id.toCaseFolded();
}
class DeviceDelegate final : public QStyledItemDelegate
{
  public:
    using QStyledItemDelegate::QStyledItemDelegate;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        const int width = option.widget ? option.widget->width() : 700;
        const auto body = index.data(DeviceSelector::DescriptionRole).toString();
        const auto rect =
            option.fontMetrics.boundingRect(QRect(0, 0, std::max(250, width - 30), 1000), Qt::TextWordWrap, body);
        return {width, std::max(rect.height(), option.fontMetrics.height()) + option.fontMetrics.height() * 2 + 20};
    }
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        auto background = option;
        initStyleOption(&background, index);
        background.text.clear();
        // The base paint method would reload DisplayRole and draw the label twice.
        (option.widget ? option.widget->style() : QApplication::style())
            ->drawControl(QStyle::CE_ItemViewItem, &background, painter, option.widget);
        painter->save();
        painter->setClipRect(option.rect);
        const bool selected = option.state & QStyle::State_Selected;
        painter->setPen(QColor(selected ? "#087f83" : "#172639"));
        auto rect = option.rect.adjusted(10, 7, -10, -7);
        const int height = option.fontMetrics.height();
        auto bold = option.font;
        bold.setBold(true);
        painter->setFont(bold);
        painter->drawText(QRect(rect.left(), rect.top(), rect.width(), height), Qt::AlignLeft | Qt::AlignVCenter,
                          index.data().toString());
        painter->setFont(option.font);
        const auto desc = index.data(DeviceSelector::DescriptionRole).toString();
        const auto descRect = option.fontMetrics.boundingRect(
            QRect(rect.left(), rect.top() + height + 2, rect.width(), 1000), Qt::TextWordWrap, desc);
        painter->drawText(descRect, Qt::TextWordWrap, desc);
        painter->drawText(QRect(rect.left(), descRect.bottom() + 3, rect.width(), height),
                          Qt::AlignLeft | Qt::AlignVCenter, index.data(DeviceSelector::AddressRole).toString());
        painter->restore();
    }
};
} // namespace
DeviceChoice describeDevice(const CaptureDevice &dev, const DeviceSystemInfo &system)
{
    DeviceChoice choice;
    choice.id = QString::fromStdString(dev.id);
    choice.description = QString::fromStdString(dev.description);
    if (choice.description.isEmpty())
        choice.description = QStringLiteral("设备未提供型号说明");
    const QString lower = choice.description.toLower();
    const bool bluetooth = lower.contains("bluetooth") || lower.contains(QStringLiteral("蓝牙"));
    // These are display hints only; capture uses the unchanged Npcap ID, never the classification.
    const bool virtualHint = lower.contains("virtual") || lower.contains("vpn") || lower.contains("tunnel") ||
                             lower.contains("tap-") || lower.contains("vnic") || lower.contains("host-only");
    QString type = QStringLiteral("其他网卡");
    if (dev.loopback)
        type = QStringLiteral("本机回环");
    else if (bluetooth)
        type = QStringLiteral("蓝牙网络");
    else if (virtualHint || system.type == QNetworkInterface::Virtual)
        type = QStringLiteral("虚拟/隧道网卡");
    else if (system.type == QNetworkInterface::Wifi)
        type = QStringLiteral("无线网卡");
    else if (system.type == QNetworkInterface::Ethernet)
        type = QStringLiteral("有线以太网");
    const QString connection = system.matched ? (system.running   ? QStringLiteral("已连接")
                                                 : system.enabled ? QStringLiteral("未连接")
                                                                  : QStringLiteral("未启用"))
                                              : QStringLiteral("状态未知");
    const QString name = dev.loopback             ? QStringLiteral("本机回环")
                         : !system.name.isEmpty() ? system.name
                                                  : choice.description;
    choice.title = name + " · " + type + " · " + connection;
    if (system.running && !virtualHint && !bluetooth &&
        (system.type == QNetworkInterface::Wifi || system.type == QNetworkInterface::Ethernet))
        choice.priority = 0;
    else if (!virtualHint && !bluetooth &&
             (system.type == QNetworkInterface::Wifi || system.type == QNetworkInterface::Ethernet))
        choice.priority = 1;
    else if (dev.loopback)
        choice.priority = 2;
    else if (system.running)
        choice.priority = 3;
    QStringList ipv4, ipv6;
    for (const auto &address : dev.addresses)
    {
        const auto s = QString::fromStdString(address);
        (s.contains(':') ? ipv6 : ipv4).append(s);
    }
    choice.addressSummary = QStringLiteral("IPv4：%1    IPv6：%2 个地址")
                                .arg(ipv4.isEmpty() ? QStringLiteral("无") : ipv4.join(", "))
                                .arg(ipv6.size());
    choice.details = QStringLiteral("网卡：%1\n型号：%2\nIPv4：%3\nIPv6：%4")
                         .arg(choice.title, choice.description, ipv4.isEmpty() ? QStringLiteral("无") : ipv4.join(", "),
                              ipv6.isEmpty() ? QStringLiteral("无") : ipv6.join(", "));
    return choice;
}
QList<DeviceChoice> captureDeviceChoices(const std::vector<CaptureDevice> &devices)
{
    const auto interfaces = systemDeviceInfo();
    QList<DeviceChoice> result;
    for (const auto &dev : devices)
    {
        const auto info = interfaces.value(key(QString::fromStdString(dev.id)));
        result.append(describeDevice(dev, info));
    }
    std::stable_sort(result.begin(), result.end(),
                     [](const auto &a, const auto &b) { return a.priority < b.priority; });
    return result;
}
DeviceSelector::DeviceSelector(QWidget *parent) : QComboBox(parent)
{
    setObjectName("captureDevice");
    setMinimumWidth(290);
    setMaximumWidth(390);
    setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    setMinimumContentsLength(20);
    setItemDelegate(new DeviceDelegate(view()));
    view()->setTextElideMode(Qt::ElideNone);
    setMaxVisibleItems(6);
}
void DeviceSelector::setChoices(const QList<DeviceChoice> &choices)
{
    const QString selected = currentData().toString();
    clear();
    for (const auto &choice : choices)
    {
        addItem(choice.title, choice.id);
        const int i = count() - 1;
        setItemData(i, choice.description, DescriptionRole);
        setItemData(i, choice.addressSummary, AddressRole);
        setItemData(i, choice.details, DetailsRole);
        setItemData(i, choice.details + "\nNpcap ID：" + choice.id, Qt::ToolTipRole);
    }
    const int old = findData(selected);
    if (old >= 0)
        setCurrentIndex(old);
}
QString DeviceSelector::selectedDetails() const
{
    return currentData(DetailsRole).toString();
}
void DeviceSelector::showPopup()
{
    const int screenWidth = screen() ? screen()->availableGeometry().width() - 30 : 1000;
    int desired = 700;
    for (int i = 0; i < count(); ++i)
        desired = std::max(desired, fontMetrics().horizontalAdvance(itemData(i, DescriptionRole).toString()) + 40);
    const int popupWidth = std::min(desired, screenWidth);
    view()->setMinimumWidth(std::max(width(), popupWidth));
    QComboBox::showPopup();
}
} // namespace flowguard
