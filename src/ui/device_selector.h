// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#pragma once
#include "core/module_contracts.h"
#include <QComboBox>
#include <QMap>
#include <QNetworkInterface>

namespace flowguard
{
struct DeviceSystemInfo
{
    QString name;
    QNetworkInterface::InterfaceType type = QNetworkInterface::Unknown;
    bool matched = false;
    bool enabled = false;
    bool running = false;
};
// Windows metadata is keyed by the GUID also used by Npcap.
QMap<QString, DeviceSystemInfo> systemDeviceInfo();
struct DeviceChoice
{
    QString id, title, description, addressSummary, details;
    int priority = 5;
};
DeviceChoice describeDevice(const CaptureDevice &, const DeviceSystemInfo &);
QList<DeviceChoice> captureDeviceChoices(const std::vector<CaptureDevice> &);
class DeviceSelector final : public QComboBox
{
  public:
    enum Role
    {
        DescriptionRole = Qt::UserRole + 1,
        AddressRole,
        DetailsRole
    };
    explicit DeviceSelector(QWidget *parent = nullptr);
    void setChoices(const QList<DeviceChoice> &);
    QString selectedDetails() const;
    void showPopup() override;
};
} // namespace flowguard
