/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <Saver.hpp>
#include <Stats.hpp>
#include <ctime>
#include <string>

#pragma once

class BlockingList {
public:
    BlockingList();

    BlockingList(const std::string id, const std::string name, const std::string url,
                 const Stats::Color _color, uint8_t _blockMask, const std::time_t updatedAt,
                 const bool outdated, const std::string etag, const bool enabled,
                 const uint32_t domainsCount);

    void save(Saver &saver) const;

    void restore(Saver &saver);

    void refreshList(const std::string lastUpdated, const std::string etag);

    void updateList(const std::string name, const Stats::Color color, const std::string url,
                    const uint8_t blockMask, const uint32_t domainsCount, const time_t updatedAt,
                    const std::string etag, const bool enabled, const bool outdated);

    void toggleList();

    std::string getId() const;

    std::string getName() const;

    std::string getUrl() const;

    Stats::Color getColor() const;

    std::uint8_t getBlockMask() const;

    std::time_t getUpdatedAt() const;

    std::uint32_t getDomainsCount() const;

    bool isOutdated() const;

    void setIsOutDated();

    std::string getEtag() const;

    bool isEnabled() const;

    void enable();

    void disable();

    std::string serialize() const;

private:
    std::string _id;
    std::string _name;
    std::string _url;
    Stats::Color _color;
    uint8_t _blockMask;
    std::time_t _updatedAt = 0;
    bool _outdated = true;
    std::string _etag = "";
    bool _enabled = true;
    uint32_t _domainsCount;
};