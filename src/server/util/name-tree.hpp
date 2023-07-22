/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2021-2022,  The University of Memphis
 *
 * This file is part of mGuard.
 * Author: Saurab Dulal <dulal.saurab@gmail.com>
 *
 * mGuard is free software: you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * mGuard is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * mGuard, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef MGUARD_UTIL_NAMETREE_HPP
#define MGUARD_UTIL_NAMETREE_HPP

#include <ndn-cxx/name.hpp>
#include <ndn-cxx/util/logger.hpp>

namespace mguard {
namespace util {
namespace nametree {

// const ndn::Name ignoreDefaultPrefix("/mguard/ignore");

struct TreeNode
{
  std::vector<TreeNode*> m_children;
  std::string m_nodeId; // this is the last name component e.g. for name /aa/bb/cc this will be cc
  ndn::Name m_fullName; // this is complete name from root /aa/bb/cc
};

/*
  
  m-arrary tree or general tree, used to store hierarchical ndn names
  e.g. inserting names /aa/bb/cc, /aa/ff/kk, /aa/ff/mm/cc will result in the following tree structure

                                        / -> root of the tree
                                        |
                                        aa  (e.g. m_fullName = /aa)
                                  ++++++++++++++
                                  |            |
                                  bb           ff
                                        +++++++++++++++
                                        |             |
                                        kk            mm
                                                       |
                                                       cc (e.g. m_fullname = /aa/ff/mm/cc)


*/
class NameTree
{
public:
  NameTree();
  
  TreeNode*
  getTreeRoot()
  {
    return m_root;
  }

  void
  insertName(ndn::Name name);

  /** 
   * @brief Search if a name exist in the tree, return node pointer if the name is found
   *  @param startFrom node pointer, starting node of the getNode
   *  @param name name prefix to getNode for
  */
  std::optional<TreeNode*>
  getNode(TreeNode* startFrom, ndn::Name name);

  /** 
   * @brief get all the leaf (names) of a name prefix in the tree
   *  @param name name to get leafs for
   *  for the above example, if the prefix is aa, this function will return /aa/bb,
   *  /aa/ff/kk, /aa/ff/kk/mm/cc
  */
  std::vector<ndn::Name>
  getLeaves(ndn::Name prefix, const std::vector<ndn::Name>& ignore);
  
  TreeNode*
  getParent(ndn::Name name);

  /** 
   * @brief get all the childrens (names) of a name prefix in the tree
   *  @param name name to get childrens for
   *  for the above example, if the name prefix is aa, this function will return /aa/bb,
   *  /aa/ff, /aa/ff/kk, /aa/ff/kk/mm, /aa/ff/kk/mm/cc
  */
  std::vector<ndn::Name>
  getChildren(ndn::Name name);

  /* return logest match prefix of a name */
  ndn::Name
  longestPrefixMatch(ndn::Name name);

  void
  deleteNode(const ndn::Name& prefix);

  void
  _printTree(TreeNode* startFrom);

  bool
  isChild(TreeNode* node, const ndn::Name& leaf);

  TreeNode*
  findNode(ndn::Name target);

  TreeNode*
  findNode(std::vector<TreeNode*> children, ndn::Name& target);

private:
  static TreeNode*
  createNode(std::string nodeId, const ndn::Name& fullName);

  void
  getLeaves(TreeNode* startFrom, std::vector<ndn::Name>& leaves, const std::vector<ndn::Name>& ignore);

  std::pair<TreeNode*, ndn::Name>
  getLongestMatchedName(TreeNode* startFrom, ndn::Name& namePrefix);

  void
  getChildren(TreeNode* startFrom, std::vector<ndn::Name>& children);

  void
  _delete(TreeNode* nodeptr);

private:
  TreeNode* m_root;
};
} // nametree
} // util
} // mguard

#endif