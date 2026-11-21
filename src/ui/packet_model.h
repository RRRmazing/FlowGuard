// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#pragma once
#include "core/module_contracts.h"
#include <QAbstractTableModel>
#include <deque>

namespace flowguard
{
QString protocolName(const PacketRecord &);
class PacketModel final : public QAbstractTableModel
{
  public:
    using QAbstractTableModel::QAbstractTableModel;
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &, int role = Qt::DisplayRole) const override;
    QVariant headerData(int, Qt::Orientation, int role) const override;
    void append(std::vector<ParsedPacket> packets);
    void clear();
    void filter(DisplayFilter);
    const ParsedPacket *packet(int row) const;
    std::size_t retained() const
    {
        return history_.size();
    }
    std::uint64_t evicted() const
    {
        return evicted_;
    }

  private:
    void rebuild();
    std::deque<ParsedPacket> history_;
    std::vector<std::size_t> visible_;
    DisplayFilter filter_;
    std::uint64_t evicted_ = 0;
};
} // namespace flowguard
